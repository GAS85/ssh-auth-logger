package abuse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// blocklist.de HTTP reporting API: https://www.blocklist.de/en/httpreports.html?help
const (
	blocklistDeURL = "https://www.blocklist.de/en/httpreports.html"

	// Upper bound for the "logs" field, whole lines only.
	blocklistDeMaxLogsLen = 8192
	// Per-field cap for attacker-controlled values placed in a log line.
	blocklistDeMaxFieldLen = 128
)

// blocklistDeBackend reports abusive IPs to https://www.blocklist.de
//
// Reports are sent per IP, like AbuseIPDB. The "logs" field is built from the credentials collected for the IP, one log line per distinct attempt.
type blocklistDeBackend struct {
	server string // "Server-E-Mail": the e-mail address or server ID of the reporting account
	apiKey string

	// Service names as accepted by blocklist.de (see the list on the help page). An empty value means: do not report this protocol.
	sshService    string
	telnetService string

	reportClearUsername  bool
	reportClearPassword  bool
	reportHashedPassword bool

	endpoint   string
	httpClient *http.Client
}

// newBlocklistDeFromEnv builds the blocklist.de backend from BLOCKLIST_* variables. Returns (nil, nil) if BLOCKLIST_ENABLED is not set.
func newBlocklistDeFromEnv() (Backend, logrus.Fields) {
	if !envBool("BLOCKLIST_ENABLED", "false") {
		return nil, nil
	}

	server := getenv("BLOCKLIST_SERVER", "")
	apiKey := getenv("BLOCKLIST_API_KEY", "")
	if server == "" || apiKey == "" {
		logrus.Fatal("BLOCKLIST_ENABLED is enabled but BLOCKLIST_SERVER or BLOCKLIST_API_KEY is empty")
	}

	clearUsername := envBool("BLOCKLIST_REPORT_CLEAR_USERNAME", "true")
	clearPassword := envBool("BLOCKLIST_REPORT_CLEAR_PASSWORD", "false")
	// BLOCKLIST_REPORT_HASHED_PASSWORD overrides BLOCKLIST_REPORT_CLEAR_PASSWORD when enabled.
	hashedPassword := envBool("BLOCKLIST_REPORT_HASHED_PASSWORD", "true")

	b := &blocklistDeBackend{
		server: server,
		apiKey: apiKey,

		sshService: getenv("BLOCKLIST_SSH_SERVICE", "ssh-auth"),
		// blocklist.de has no "telnet" service in its published list. Will set one from apache
		// https://www.blocklist.de/en/download.html#services
		telnetService: getenv("BLOCKLIST_TELNET_SERVICE", "bruteforcelogin"),

		reportClearUsername:  clearUsername,
		reportClearPassword:  clearPassword && !hashedPassword,
		reportHashedPassword: hashedPassword,

		endpoint: blocklistDeURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			// The API key must never follow a redirect to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}

	// The server e-mail / API key are deliberately not part of the startup log.
	return b, logrus.Fields{
		"blocklist": logrus.Fields{
			"BLOCKLIST_ENABLED":                true,
			"BLOCKLIST_SSH_SERVICE":            b.sshService,
			"BLOCKLIST_TELNET_SERVICE":         b.telnetService,
			"BLOCKLIST_REPORT_CLEAR_USERNAME":  b.reportClearUsername,
			"BLOCKLIST_REPORT_CLEAR_PASSWORD":  b.reportClearPassword,
			"BLOCKLIST_REPORT_HASHED_PASSWORD": b.reportHashedPassword,
		},
	}
}

func (b *blocklistDeBackend) Name() string { return "blocklist.de" }

// Sanitize keeps usernames / passwords only if explicitly enabled.
// Hashed passwords are cut to the first 8 symbols (same as the other backends).
func (b *blocklistDeBackend) Sanitize(username, password string) (string, string) {
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

// serviceFor maps the honeypot protocol to a blocklist.de service name ("" = do not report).
func (b *blocklistDeBackend) serviceFor(protocol string) string {
	if strings.EqualFold(protocol, "Telnet") {
		return b.telnetService
	}
	return b.sshService
}

// buildLogs renders the collected attempts as log lines. Attacker-controlled values are quoted with %q, so a username containing a newline cannot forge additional log lines. Output is capped at blocklistDeMaxLogsLen bytes, whole lines only.
func (b *blocklistDeBackend) buildLogs(rep Report) string {
	creds := rep.Creds
	if len(creds) == 0 {
		creds = []Credential{{Time: time.Now()}}
	}

	var sb strings.Builder
	for _, c := range creds {
		line := fmt.Sprintf("%s ssh-auth-logger: Failed %s authentication from %s",
			c.Time.UTC().Format(time.RFC3339), rep.Protocol, rep.IP)

		if c.Username != "" {
			line += fmt.Sprintf(" user=%q", truncateUTF8(c.Username, blocklistDeMaxFieldLen))
		}
		if c.Password != "" {
			label := "password"
			if b.reportHashedPassword {
				label = "password_sha1_prefix"
			}
			line += fmt.Sprintf(" %s=%q", label, truncateUTF8(c.Password, blocklistDeMaxFieldLen))
		}
		line += "\n"

		if sb.Len()+len(line) > blocklistDeMaxLogsLen {
			break
		}
		sb.WriteString(line)
	}

	return sb.String()
}

// blocklistDeResponse is the reply for format=json: "status" plus "error" (0 on success, otherwise the error message(s)).
type blocklistDeResponse struct {
	Status string          `json:"status"`
	Error  json.RawMessage `json:"error"`
}

// parseBlocklistDeResponse evaluates the reply body. The API documents success as "$error is 0 or $status is 'success'". The HTTP status alone cannot be trusted, errors may come with 200 OK.
func parseBlocklistDeResponse(body []byte) (ok bool, detail string) {
	var r blocklistDeResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return false, "unparseable response: " + truncateUTF8(strings.TrimSpace(string(body)), 512)
	}

	switch {
	case strings.EqualFold(r.Status, "success"):
		return true, ""
	case strings.EqualFold(r.Status, "error"):
		// An explicit error status always wins, even if the error list is empty.
	default:
		switch strings.TrimSpace(string(r.Error)) {
		case "0", `"0"`, "false", `""`, "[]", "{}":
			return true, ""
		}
	}

	// A failure without a meaningful message (missing, null, 0, empty list) would otherwise be logged as a confusing "error: 0".
	raw := strings.TrimSpace(string(r.Error))
	switch raw {
	case "", "null", "0", `"0"`, "false", `""`, "[]", "{}":
		return false, "status=" + r.Status + " (no error message)"
	}
	return false, truncateUTF8(raw, 512)
}

// Report sends the actual blocklist.de request.
func (b *blocklistDeBackend) Report(rep Report) {
	service := b.serviceFor(rep.Protocol)
	if service == "" {
		logger.WithFields(logrus.Fields{
			"ip":       rep.IP,
			"protocol": rep.Protocol,
		}).Debugf("blocklist.de: no service configured for %s, not reporting", rep.Protocol)
		return
	}

	form := url.Values{}
	form.Set("server", b.server)
	form.Set("apikey", b.apiKey)
	form.Set("ip", rep.IP)
	form.Set("service", service)
	form.Set("format", "json")
	form.Set("logs", b.buildLogs(rep))

	// POST with the key in the body (not the URL), so it does not end up in proxy or access logs. The API accepts GET and POST.
	req, err := http.NewRequest(http.MethodPost, b.endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		logger.WithError(err).WithField("ip", rep.IP).Error("blocklist.de: failed to create request")
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		logger.WithError(err).WithField("ip", rep.IP).Error("blocklist.de: request failed")
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	fields := logrus.Fields{
		"ip":       rep.IP,
		"protocol": rep.Protocol,
		"service":  service,
		"status":   resp.Status,
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fields["body"] = string(body)
		logger.WithFields(fields).Warnf("blocklist.de: report rejected for %s", rep.IP)
		return
	}

	if ok, detail := parseBlocklistDeResponse(body); !ok {
		fields["error"] = detail
		logger.WithFields(fields).Warnf("blocklist.de: report rejected for %s", rep.IP)
		return
	}

	logger.WithFields(fields).Infof("blocklist.de: IP %s reported", rep.IP)
}
