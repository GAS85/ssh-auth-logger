package abuse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Spamhaus Submission Portal API: https://submit.spamhaus.org/api/
// API key: https://auth.spamhaus.org/account ("API Key Creation"), shown only once.
const (
	spamhausDefaultURL = "https://submit.spamhaus.org/portal/api/v1/submissions/add/ip"

	// Maximum length of the "reason" field, documented by Spamhaus.
	spamhausMaxReasonLen = 255
)

// spamhausSubmission is the request body of POST submissions/add/ip.
type spamhausSubmission struct {
	ThreatType string         `json:"threat_type"`
	Reason     string         `json:"reason"`
	Source     spamhausSource `json:"source"`
}

type spamhausSource struct {
	Object string `json:"object"` // the IP address
}

// spamhausBackend reports abusive IPs to https://submit.spamhaus.org
//
// Reports are sent per IP, like AbuseIPDB. No usernames or passwords are ever collected or transmitted: Sanitize drops them before they are stored, and the request has no field for them.
type spamhausBackend struct {
	apiKey     string
	threatType string

	endpoint   string
	httpClient *http.Client
}

// newSpamhausFromEnv builds the Spamhaus backend from SPAMHAUS_* variables. Returns (nil, nil) if SPAMHAUS_ENABLED is not set.
func newSpamhausFromEnv() (Backend, logrus.Fields) {
	if !envBool("SPAMHAUS_ENABLED", "false") {
		return nil, nil
	}

	apiKey := getenv("SPAMHAUS_API_KEY", "")
	if apiKey == "" {
		logrus.Fatal("SPAMHAUS_ENABLED is enabled but SPAMHAUS_API_KEY is empty")
	}

	b := &spamhausBackend{
		apiKey: apiKey,
		// Valid codes can be listed with GET /portal/api/v1/lookup/threats-types
		threatType: strings.TrimSpace(getenv("SPAMHAUS_THREAT_TYPE", "attack")),

		endpoint: spamhausDefaultURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			// The bearer token must never follow a redirect to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}

	return b, logrus.Fields{
		"spamhouse": logrus.Fields{
			"SPAMHAUS_ENABLED":     true,
			"SPAMHAUS_THREAT_TYPE": b.threatType,
		},
	}
}

func (b *spamhausBackend) Name() string { return "Spamhaus" }

// Sanitize drops everything: usernames and passwords are never retained or sent to Spamhaus.
func (b *spamhausBackend) Sanitize(string, string) (string, string) { return "", "" }

// reasonFor builds the submission reason, worded like the AbuseIPDB comment. It is limited to Spamhaus' 255 characters.
func reasonFor(protocol, ip string) string {
	if protocol == "" {
		protocol = "SSH/Telnet"
	}
	reason := fmt.Sprintf(
		"%s authentication brute-force attempt against GAS85/ssh-auth-logger honeypot from %s",
		protocol,
		ip,
	)
	return truncateUTF8(reason, spamhausMaxReasonLen)
}

// Report sends the actual Spamhaus request.
func (b *spamhausBackend) Report(rep Report) {
	body, err := json.Marshal(spamhausSubmission{
		ThreatType: b.threatType,
		Reason:     reasonFor(rep.Protocol, rep.IP),
		Source:     spamhausSource{Object: rep.IP},
	})
	if err != nil {
		logger.WithError(err).WithField("ip", rep.IP).Error("Spamhaus: failed to encode request")
		return
	}

	req, err := http.NewRequest(http.MethodPost, b.endpoint, bytes.NewReader(body))
	if err != nil {
		logger.WithError(err).WithField("ip", rep.IP).Error("Spamhaus: failed to create request")
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+b.apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		logger.WithError(err).WithField("ip", rep.IP).Error("Spamhaus: request failed")
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	fields := logrus.Fields{
		"ip":       rep.IP,
		"protocol": rep.Protocol,
		"status":   resp.Status,
	}

	switch {
	case resp.StatusCode == http.StatusAlreadyReported:
		// Documented, not an error: Spamhaus already holds this IP.
		logger.WithFields(fields).Infof("Spamhaus: IP %s already reported", rep.IP)

	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		var ok struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(respBody, &ok) == nil && ok.ID != "" {
			fields["id"] = ok.ID
		}
		logger.WithFields(fields).Infof("Spamhaus: IP %s reported", rep.IP)

	default:
		// Read a bounded amount of the body: it carries the actual reason ("invalid IP address provided", "user is not authorized", invalid threat_type, ...).
		fields["body"] = string(respBody)
		logger.WithFields(fields).Warnf("Spamhaus: report rejected for %s", rep.IP)
	}
}
