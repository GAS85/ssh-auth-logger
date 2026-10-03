package abuse

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Maximum comment length (bytes) https://www.abuseipdb.com/api.html
const abuseIPDBMaxCommentLen = 1024

// abuseIPDBBackend reports abusive IPs to https://www.abuseipdb.com
type abuseIPDBBackend struct {
	apiKey string

	sshCategories    string
	telnetCategories string

	reportClearUsername  bool
	reportClearPassword  bool
	reportHashedPassword bool

	httpClient *http.Client
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

	b := &abuseIPDBBackend{
		apiKey:           apiKey,
		sshCategories:    sshCategories,
		telnetCategories: telnetCategories,

		reportClearUsername: clearUsername,
		// reportHashedPassword takes precedence over reportClearPassword. If both are set, cleartext passwords are never collected or sent
		reportClearPassword:  clearPassword && !hashedPassword,
		reportHashedPassword: hashedPassword,

		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	return b, logrus.Fields{
		"ABUSEIPDB_ENABLED":                true,
		"ABUSEIPDB_SSH_CATEGORIES":         b.sshCategories,
		"ABUSEIPDB_TELNET_CATEGORIES":      b.telnetCategories,
		"ABUSEIPDB_REPORT_CLEAR_USERNAME":  b.reportClearUsername,
		"ABUSEIPDB_REPORT_CLEAR_PASSWORD":  b.reportClearPassword,
		"ABUSEIPDB_REPORT_HASHED_PASSWORD": b.reportHashedPassword,
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
