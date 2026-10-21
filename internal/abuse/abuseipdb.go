package abuse

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Maximum comment length (bytes) https://www.abuseipdb.com/api.html
const abuseIPDBMaxCommentLen = 1024

const (
	// Only reports newer than this many days count for the confidence score (API default and maximum used by the web UI).
	abuseIPDBCheckMaxAgeDays = 30

	// Pause of reputation lookups after HTTP 429 if the response has no usable Retry-After header, and the longest pause honoured.
	abuseIPDBDefaultPause = 15 * time.Minute
	abuseIPDBMaxPause     = 24 * time.Hour
)

// errAbuseIPDBPaused is returned by LookupReputation while the API quota is exhausted.
var errAbuseIPDBPaused = errors.New("AbuseIPDB: reputation checks paused after rate limit")

// abuseIPDBBackend reports abusive IPs to https://www.abuseipdb.com
type abuseIPDBBackend struct {
	apiKey string

	sshCategories    string
	telnetCategories string

	reportClearUsername  bool
	reportClearPassword  bool
	reportHashedPassword bool

	// checkIP enables reputation lookups for connecting IPs (ABUSEIPDB_IP_CHECK).
	checkIP bool

	httpClient *http.Client

	// Lookups are suspended until pausedUntil after the API answered 429.
	pauseMu     sync.Mutex
	pausedUntil time.Time
}

// newAbuseIPDBFromEnv builds the AbuseIPDB backend from ABUSEIPDB_* variables. Returns (nil, nil) if ABUSEIPDB_ENABLED is not set.
func newAbuseIPDBFromEnv() (Backend, logrus.Fields) {
	if !envBool("ABUSEIPDB_ENABLED", "false") {
		return nil, nil
	}

	apiKey := getenv("ABUSEIPDB_API_KEY", "")
	if apiKey == "" {
		logrus.Fatal("ABUSEIPDB_ENABLED is enabled but ABUSEIPDB_API_KEY is empty")
	}

	// 18=Brute-Force, 22=SSH
	sshCategories := getenv("ABUSEIPDB_SSH_CATEGORIES", "18,22")
	// 14=Port Scan, 18=Brute-Force, 23=IoT Targeted
	telnetCategories := getenv("ABUSEIPDB_TELNET_CATEGORIES", "14,18,23")

	clearUsername := envBool("ABUSEIPDB_REPORT_CLEAR_USERNAME", "false")
	clearPassword := envBool("ABUSEIPDB_REPORT_CLEAR_PASSWORD", "false")
	// ABUSEIPDB_REPORT_HASHED_PASSWORD overrides ABUSEIPDB_REPORT_CLEAR_PASSWORD when enabled, SHA-1 hashes are reported instead of cleartext passwords.
	hashedPassword := envBool("ABUSEIPDB_REPORT_HASHED_PASSWORD", "true")
	// Look up the reputation of every connecting IP (country, confidence score, total reports) and add it to the connection log.
	checkIP := envBool("ABUSEIPDB_IP_CHECK", "false")

	b := &abuseIPDBBackend{
		apiKey:           apiKey,
		sshCategories:    sshCategories,
		telnetCategories: telnetCategories,

		reportClearUsername: clearUsername,
		// reportHashedPassword takes precedence over reportClearPassword. If both are set, cleartext passwords are never collected or sent
		reportClearPassword:  clearPassword && !hashedPassword,
		reportHashedPassword: hashedPassword,

		checkIP: checkIP,

		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	return b, logrus.Fields{
		"abuseipdb": logrus.Fields{
			"ABUSEIPDB_ENABLED":                true,
			"ABUSEIPDB_SSH_CATEGORIES":         b.sshCategories,
			"ABUSEIPDB_TELNET_CATEGORIES":      b.telnetCategories,
			"ABUSEIPDB_REPORT_CLEAR_USERNAME":  b.reportClearUsername,
			"ABUSEIPDB_REPORT_CLEAR_PASSWORD":  b.reportClearPassword,
			"ABUSEIPDB_REPORT_HASHED_PASSWORD": b.reportHashedPassword,
			"ABUSEIPDB_IP_CHECK":               b.checkIP,
		},
	}
}

func (b *abuseIPDBBackend) Name() string { return "AbuseIPDB" }

// Sanitize keeps usernames / passwords only if explicitly enabled. Hashed passwords are cut to the first 8 symbols, as a full SHA1 is easy to revert (kind of k-anonymity model).
func (b *abuseIPDBBackend) Sanitize(username, password string) (string, string) {
	if !b.reportClearUsername {
		username = ""
	}

	switch {
	case password == "":
	case b.reportHashedPassword:
		password = sha1Hex(password)[:8]
	case b.reportClearPassword:
	default:
		password = ""
	}

	return username, password
}

// categoriesFor returns the AbuseIPDB category list to use for the given protocol
func (b *abuseIPDBBackend) categoriesFor(protocol string) string {
	if strings.EqualFold(protocol, "Telnet") {
		return b.telnetCategories
	}
	return b.sshCategories
}

// Report sends the actual AbuseIPDB request.
func (b *abuseIPDBBackend) Report(rep Report) {
	ip := rep.IP
	protocol := rep.Protocol

	var usernames, passwords []string
	for _, c := range rep.Creds {
		if c.Username != "" {
			usernames = appendUnique(usernames, c.Username)
		}
		if c.Password != "" {
			passwords = appendUnique(passwords, c.Password)
		}
	}

	comment := fmt.Sprintf(
		"%s authentication brute-force attempt against GAS85/ssh-auth-logger honeypot from %s",
		protocol,
		ip,
	)

	if b.reportClearUsername && len(usernames) > 0 {
		comment += fmt.Sprintf(
			"; usernames=%q",
			usernames,
		)
	}

	if (b.reportClearPassword || b.reportHashedPassword) && len(passwords) > 0 {
		field := "passwords"
		if b.reportHashedPassword {
			field = "passwords sha1 prefix"
		}
		comment += fmt.Sprintf(
			"; %s=%q",
			field,
			passwords,
		)
	}

	comment = truncateUTF8(comment, abuseIPDBMaxCommentLen)

	form := url.Values{}
	form.Set("ip", ip)
	form.Set("categories", b.categoriesFor(protocol))
	form.Set("comment", comment)
	form.Set("timestamp", time.Now().UTC().Format(time.RFC3339))

	req, err := http.NewRequest(
		http.MethodPost,
		"https://api.abuseipdb.com/api/v2/report",
		bytes.NewBufferString(form.Encode()),
	)
	if err != nil {
		logger.WithError(err).
			WithField("ip", ip).
			Error("AbuseIPDB: failed to create request")
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Key", b.apiKey)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		logger.WithError(err).
			WithField("ip", ip).
			Error("AbuseIPDB: request failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read a bounded amount of the body and put the actual rejection reason (bad category, invalid IP, rate limit, etc.) in the JSON error response, which is otherwise thrown away.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

		logger.WithFields(logrus.Fields{
			"ip":       ip,
			"status":   resp.Status,
			"protocol": protocol,
			"body":     string(body),
		}).Warnf("AbuseIPDB: report rejected for %s", ip)

		return
	}

	logger.WithFields(logrus.Fields{
		"ip":       ip,
		"protocol": protocol,
	}).Infof("AbuseIPDB: IP %s reported", ip)
}

// ReputationCheckEnabled implements ReputationChecker.
func (b *abuseIPDBBackend) ReputationCheckEnabled() bool { return b.checkIP }

// LookupReputation implements ReputationChecker: it calls the AbuseIPDB CHECK endpoint https://docs.abuseipdb.com/#check-endpoint
// Errors are logged here; the caller only needs to know that there is no data.
func (b *abuseIPDBBackend) LookupReputation(ip string) (Reputation, error) {
	if b.isPaused() {
		return Reputation{}, errAbuseIPDBPaused
	}

	q := url.Values{}
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", strconv.Itoa(abuseIPDBCheckMaxAgeDays))

	req, err := http.NewRequest(http.MethodGet, "https://api.abuseipdb.com/api/v2/check?"+q.Encode(), nil)
	if err != nil {
		logger.WithError(err).WithField("ip", ip).Error("AbuseIPDB: failed to create check request")
		return Reputation{}, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Key", b.apiKey)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		logger.WithError(err).WithField("ip", ip).Error("AbuseIPDB: check request failed")
		return Reputation{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

		fields := logrus.Fields{
			"ip":     ip,
			"status": resp.Status,
			"body":   string(body),
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			pause := b.pauseFor(resp.Header.Get("Retry-After"))
			fields["paused_for"] = pause.String()
		}
		logger.WithFields(fields).Warnf("AbuseIPDB: reputation check rejected for %s", ip)

		return Reputation{}, fmt.Errorf("AbuseIPDB: check rejected: %s", resp.Status)
	}

	var payload struct {
		Data struct {
			CountryCode          string `json:"countryCode"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			TotalReports         int    `json:"totalReports"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		logger.WithError(err).WithField("ip", ip).Error("AbuseIPDB: invalid check response")
		return Reputation{}, err
	}

	return Reputation{
		CountryCode:          payload.Data.CountryCode,
		AbuseConfidenceScore: payload.Data.AbuseConfidenceScore,
		TotalReports:         payload.Data.TotalReports,
	}, nil
}

// isPaused reports whether lookups are suspended because of a rate limit.
func (b *abuseIPDBBackend) isPaused() bool {
	b.pauseMu.Lock()
	defer b.pauseMu.Unlock()
	return time.Now().Before(b.pausedUntil)
}

// pauseFor suspends lookups after HTTP 429, for the duration in the Retry-After header (seconds) if present, else a default, and returns it.
func (b *abuseIPDBBackend) pauseFor(retryAfter string) time.Duration {
	pause := abuseIPDBDefaultPause
	if secs, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && secs > 0 {
		pause = time.Duration(secs) * time.Second
	}
	if pause > abuseIPDBMaxPause {
		pause = abuseIPDBMaxPause
	}

	b.pauseMu.Lock()
	b.pausedUntil = time.Now().Add(pause)
	b.pauseMu.Unlock()

	return pause
}
