package abuse

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// DShield / SANS Internet Storm Center log submission API.
// Protocol reference: Cowrie's output_dshield plugin (https://github.com/cowrie/cowrie), account and auth key: https://isc.sans.edu/myreports.html
const (
	dshieldSubmitURL      = "https://www.dshield.org/submitapi/"
	dshieldDebugSubmitURL = "https://www.dshield.org/devsubmitapi/"

	// Credential length cap per field, attackers can send arbitrary garbage.
	dshieldMaxFieldLen = 256
	// If the API is unreachable, keep at most batchSize*dshieldMaxQueueFactor entries; the oldest are dropped first.
	dshieldMaxQueueFactor = 4
)

// dshieldLogEntry is one login attempt in the schema expected by the submit API.
// lastcommand / hassh / banner are not collected by this honeypot and are sent empty.
type dshieldLogEntry struct {
	Timestamp   string `json:"timestamp"`
	SourceIP    string `json:"source_ip"`
	User        string `json:"user"`
	Password    string `json:"password"`
	LastCommand string `json:"lastcommand"`
	Hassh       string `json:"hassh"`
	Banner      string `json:"banner"`
}

type dshieldPayload struct {
	Type       string            `json:"type"`
	Logs       []dshieldLogEntry `json:"logs"`
	AuthHeader string            `json:"authheader"`
}

// dshieldBackend submits login attempts to https://isc.sans.edu
// Unlike AbuseIPDB (one report per IP), DShield expects log lines, so entries from all IPs are queued and sent in batches.
type dshieldBackend struct {
	userID   string
	apiKey   string
	debug    bool
	endpoint string

	batchSize  int
	flushEvery time.Duration

	reportClearUsername  bool
	reportClearPassword  bool
	reportHashedPassword bool

	httpClient *http.Client

	mu    sync.Mutex
	batch []dshieldLogEntry

	done     chan struct{} // closed by stop
	loopDone chan struct{} // closed when flushLoop has exited
	stopOnce sync.Once
}

// newDShieldFromEnv builds the DShield backend from DSHIELD_* variables. Returns (nil, nil) if DSHIELD_ENABLED is not set.
func newDShieldFromEnv() (Backend, logrus.Fields) {
	if !envBool("DSHIELD_ENABLED", "false") {
		return nil, nil
	}

	userID := getenv("DSHIELD_USERID", "")
	apiKey := getenv("DSHIELD_API_KEY", "")
	if userID == "" || apiKey == "" {
		logrus.Fatal("DSHIELD_ENABLED is enabled but DSHIELD_USERID or DSHIELD_API_KEY is empty")
	}

	batchSize, err := strconv.Atoi(getenv("DSHIELD_BATCH_SIZE", "50"))
	if err != nil || batchSize <= 0 {
		logrus.Fatal("Invalid DSHIELD_BATCH_SIZE environment variable")
	}

	flushEvery, err := time.ParseDuration(getenv("DSHIELD_BATCH_INTERVAL", "10m"))
	if err != nil || flushEvery <= 0 {
		logrus.Fatal("Invalid DSHIELD_BATCH_INTERVAL environment variable")
	}

	// DShield statistics are built from usernames / passwords, so unlike AbuseIPDB (public per-IP comments) clear credentials are on by default.
	clearUsername := envBool("DSHIELD_REPORT_CLEAR_USERNAME", "true")
	clearPassword := envBool("DSHIELD_REPORT_CLEAR_PASSWORD", "true")
	// DSHIELD_REPORT_HASHED_PASSWORD overrides DSHIELD_REPORT_CLEAR_PASSWORD when enabled.
	hashedPassword := envBool("DSHIELD_REPORT_HASHED_PASSWORD", "false")

	b := &dshieldBackend{
		userID: userID,
		apiKey: apiKey,
		// DSHIELD_DEBUG=true switches to the non-production endpoint, useful to verify credentials and format first.
		debug: envBool("DSHIELD_DEBUG", "false"),

		batchSize:  batchSize,
		flushEvery: flushEvery,

		reportClearUsername:  clearUsername,
		reportClearPassword:  clearPassword && !hashedPassword,
		reportHashedPassword: hashedPassword,

		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			// The auth header must never follow a redirect to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}

	b.endpoint = dshieldSubmitURL
	if b.debug {
		b.endpoint = dshieldDebugSubmitURL
	}

	b.done = make(chan struct{})
	b.loopDone = make(chan struct{})
	go b.flushLoop()

	return b, logrus.Fields{
		"dshield": logrus.Fields{
			"DSHIELD_ENABLED":                true,
			"DSHIELD_USERID":                 b.userID,
			"DSHIELD_BATCH_SIZE":             b.batchSize,
			"DSHIELD_BATCH_INTERVAL":         b.flushEvery.String(),
			"DSHIELD_DEBUG":                  b.debug,
			"DSHIELD_REPORT_CLEAR_USERNAME":  b.reportClearUsername,
			"DSHIELD_REPORT_CLEAR_PASSWORD":  b.reportClearPassword,
			"DSHIELD_REPORT_HASHED_PASSWORD": b.reportHashedPassword,
		},
	}
}

func (b *dshieldBackend) Name() string { return "DShield" }

// Sanitize keeps usernames / passwords only if explicitly enabled.
func (b *dshieldBackend) Sanitize(username, password string) (string, string) {
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

// Report queues the collected attempts and submits the batch once it is large enough. The remaining entries are sent by flushLoop.
func (b *dshieldBackend) Report(rep Report) {
	entries := make([]dshieldLogEntry, 0, len(rep.Creds))
	for _, c := range rep.Creds {
		entries = append(entries, dshieldLogEntry{
			Timestamp: c.Time.UTC().Format("2006-01-02T15:04:05.000000Z"),
			SourceIP:  rep.IP,
			User:      truncateUTF8(c.Username, dshieldMaxFieldLen),
			Password:  truncateUTF8(c.Password, dshieldMaxFieldLen),
		})
	}

	b.mu.Lock()
	b.batch = append(b.batch, entries...)
	full := len(b.batch) >= b.batchSize
	b.mu.Unlock()

	if full {
		b.flush()
	}
}

// flushLoop makes sure queued entries do not wait indefinitely for the batch to fill up.
func (b *dshieldBackend) flushLoop() {
	if b.loopDone != nil {
		defer close(b.loopDone)
	}

	ticker := time.NewTicker(b.flushEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.flush()
		case <-b.done: // nil channel (no stop wired up) blocks forever, i.e. runs until process exit
			return
		}
	}
}

// stop ends flushLoop and waits for it to exit. Queued entries are not flushed.
func (b *dshieldBackend) stop() {
	b.stopOnce.Do(func() {
		if b.done != nil {
			close(b.done)
		}
		if b.loopDone != nil {
			<-b.loopDone
		}
	})
}

// flush takes everything queued and submits it. On temporary failure the entries are put back in the queue.
func (b *dshieldBackend) flush() {
	b.mu.Lock()
	batch := b.batch
	b.batch = nil
	b.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	retry, err := b.submit(batch)
	if err == nil {
		return
	}

	logger.WithError(err).WithField("entries", len(batch)).Warn("DShield: submission failed")

	if !retry {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Failed entries are older than anything queued meanwhile, keep them in front.
	b.batch = append(batch, b.batch...)
	if limit := b.batchSize * dshieldMaxQueueFactor; len(b.batch) > limit {
		dropped := len(b.batch) - limit
		b.batch = b.batch[dropped:]
		logger.WithField("dropped", dropped).Warn("DShield: queue full, oldest entries dropped")
	}
}

// authHeader builds the X-ISC-Authorization value:
// HMAC-SHA256 with key = nonce+userid over the raw auth key, base64 encoded.
func (b *dshieldBackend) authHeader() (string, error) {
	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", err
	}

	return b.authHeaderWithNonce(base64.StdEncoding.EncodeToString(nonceBytes)), nil
}

// authHeaderWithNonce is split out of authHeader so the signature can be verified against a known-answer vector.
func (b *dshieldBackend) authHeaderWithNonce(nonce string) string {
	mac := hmac.New(sha256.New, []byte(nonce+b.userID))
	mac.Write([]byte(b.apiKey))
	digest := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("ISC-HMAC-SHA256 Credentials=%s Userid=%s Nonce=%s", digest, b.userID, nonce)
}

// submit sends one batch. The returned bool tells whether a retry later makes sense (network error / 5xx / 429) or not (rejected request, e.g. bad credentials).
func (b *dshieldBackend) submit(batch []dshieldLogEntry) (retry bool, err error) {
	auth, err := b.authHeader()
	if err != nil {
		return false, err
	}

	body, err := json.Marshal(dshieldPayload{
		Type:       "cowrie", // log schema understood by the submit API
		Logs:       batch,
		AuthHeader: auth,
	})
	if err != nil {
		return false, err
	}

	if b.debug {
		// Show exactly what is sent, minus the signature, so it can be compared with what the DShield dashboard displays or attached to a report to the ISC handlers.
		redacted := dshieldPayload{Type: "cowrie", Logs: batch, AuthHeader: "<redacted>"}
		if dump, mErr := json.Marshal(redacted); mErr == nil {
			logger.WithField("payload", string(dump)).Info("DShield: submitting payload (debug)")
		}
	}

	req, err := http.NewRequest(http.MethodPost, b.endpoint, bytes.NewReader(body))
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-ISC-Authorization", auth)
	req.Header.Set("X-ISC-LogType", "cowrie")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry = resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
		return retry, fmt.Errorf("status %s: %s", resp.Status, respBody)
	}

	entry := logger.WithFields(logrus.Fields{
		"entries": len(batch),
		"status":  resp.Status,
	})
	if b.debug {
		entry = entry.WithField("body", string(respBody))
	}
	entry.Info("DShield: entries submitted")

	return false, nil
}
