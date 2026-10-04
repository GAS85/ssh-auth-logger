package abuse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AlienVault OTX (Open Threat Exchange) submission.
// API reference: https://otx.alienvault.com/api, API key: https://otx.alienvault.com/settings
//
// OTX has no "report an IP" call like AbuseIPDB. Intelligence is shared as indicators inside a pulse, so this backend
// collects reported IPs, and submits them in batches: the first batch creates a pulse (POST /api/v1/pulses/create),
// every following batch is added to that same pulse (PATCH /api/v1/pulses/{id}), so one honeypot does not create
// hundreds of pulses. Set OTX_PULSE_ID to keep appending to an existing pulse across restarts.
const (
	otxDefaultBaseURL = "https://otx.alienvault.com"

	otxCreatePath = "/api/v1/pulses/create"
	otxEditPath   = "/api/v1/pulses/" // + id

	otxDefaultPulseName = "GAS85/ssh-auth-logger honeypot: SSH/Telnet brute-force sources"

	// otxReferenceURL is attached to every pulse this backend creates, as an OTX "reference".
	otxReferenceURL = "https://github.com/GAS85/ssh-auth-logger"

	// If the API is unreachable, keep at most batchSize*otxMaxQueueFactor indicators; the oldest are dropped first.
	otxMaxQueueFactor = 4
)

// otxIndicator is one entry of a pulse.
type otxIndicator struct {
	Indicator   string `json:"indicator"`
	Type        string `json:"type"` // "IPv4" or "IPv6"
	Role        string `json:"role,omitempty"`
	Description string `json:"description,omitempty"`
}

// otxCreateBody is the request body of POST /api/v1/pulses/create.
type otxCreateBody struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Public      bool           `json:"public"`
	TLP         string         `json:"TLP"`
	Tags        []string       `json:"tags"`
	References  []string       `json:"references"`
	Indicators  []otxIndicator `json:"indicators"`
}

// otxEditBody is the request body of PATCH /api/v1/pulses/{id} when adding indicators.
type otxEditBody struct {
	Indicators struct {
		Add []otxIndicator `json:"add"`
	} `json:"indicators"`
}

// otxBackend shares attacking IPs as indicators of a pulse at https://otx.alienvault.com
// No credentials are ever collected: a pulse is (by default) public, and OTX indicators are IPs only.
type otxBackend struct {
	apiKey  string
	baseURL string

	pulseName string
	public    bool
	tlp       string
	tags      []string
	role      string

	batchSize  int
	flushEvery time.Duration

	httpClient *http.Client

	// flushMu serializes flush so two concurrent flushes cannot both create a pulse.
	flushMu sync.Mutex

	mu      sync.Mutex
	pulseID string // set from OTX_PULSE_ID or from the first successful create
	batch   []otxIndicator

	done     chan struct{} // closed by stop
	loopDone chan struct{} // closed when flushLoop has exited
	stopOnce sync.Once
}

// newOTXFromEnv builds the OTX backend from OTX_* variables. Returns (nil, nil) if OTX_ENABLED is not set.
func newOTXFromEnv() (Backend, logrus.Fields) {
	if !envBool("OTX_ENABLED", "false") {
		return nil, nil
	}

	apiKey := getenv("OTX_API_KEY", "")
	if apiKey == "" {
		logrus.Fatal("OTX_ENABLED is enabled but OTX_API_KEY is empty")
	}

	batchSize, err := strconv.Atoi(getenv("OTX_BATCH_SIZE", "25"))
	if err != nil || batchSize <= 0 {
		logrus.Fatal("Invalid OTX_BATCH_SIZE environment variable")
	}

	flushEvery, err := time.ParseDuration(getenv("OTX_BATCH_INTERVAL", "1h"))
	if err != nil || flushEvery <= 0 {
		logrus.Fatal("Invalid OTX_BATCH_INTERVAL environment variable")
	}

	public := envBool("OTX_PUBLIC", "true")

	tlp := strings.ToLower(getenv("OTX_TLP", "white"))
	switch tlp {
	case "white", "green":
	case "amber", "red":
		// OTX rejects public pulses with these TLP values.
		if public {
			logrus.Fatal("Invalid OTX_TLP environment variable: amber and red pulses must be private (set OTX_PUBLIC=false)")
		}
	default:
		logrus.Fatal("Invalid OTX_TLP environment variable (use white, green, amber or red)")
	}

	var tags []string
	for _, t := range strings.Split(getenv("OTX_TAGS", "honeypot,ssh,telnet,brute-force"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = appendUnique(tags, t)
		}
	}

	b := &otxBackend{
		apiKey:  apiKey,
		baseURL: otxDefaultBaseURL,

		pulseName: getenv("OTX_PULSE_NAME", otxDefaultPulseName),
		pulseID:   getenv("OTX_PULSE_ID", ""),
		public:    public,
		tlp:       tlp,
		tags:      tags,
		// Optional OTX indicator role (e.g. "scanning_host"). An unknown role is rejected by the API.
		role: getenv("OTX_INDICATOR_ROLE", "bruteforce"),

		batchSize:  batchSize,
		flushEvery: flushEvery,

		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			// The API key header must never follow a redirect to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}

	b.done = make(chan struct{})
	b.loopDone = make(chan struct{})
	go b.flushLoop()

	return b, logrus.Fields{
		"OTX_ENABLED":        true,
		"OTX_PULSE_ID":       b.pulseID,
		"OTX_PULSE_NAME":     b.pulseName,
		"OTX_PUBLIC":         b.public,
		"OTX_TLP":            b.tlp,
		"OTX_TAGS":           strings.Join(b.tags, ","),
		"OTX_INDICATOR_ROLE": b.role,
		"OTX_BATCH_SIZE":     b.batchSize,
		"OTX_BATCH_INTERVAL": b.flushEvery.String(),
	}
}

func (b *otxBackend) Name() string { return "OTX" }

// Sanitize drops everything: OTX indicators are IP addresses, usernames and passwords are never retained or sent.
func (b *otxBackend) Sanitize(string, string) (string, string) { return "", "" }

// Report queues the IP and submits the batch once it is large enough. The remaining entries are sent by flushLoop.
func (b *otxBackend) Report(rep Report) {
	parsed := net.ParseIP(rep.IP)
	if parsed == nil {
		logger.WithField("ip", rep.IP).Warn("OTX: invalid IP address, not queued")
		return
	}

	typ := "IPv6"
	if parsed.To4() != nil {
		typ = "IPv4"
	}

	ind := otxIndicator{
		Indicator:   rep.IP,
		Type:        typ,
		Role:        b.role,
		Description: fmt.Sprintf("%s authentication brute-force attempts against a honeypot", rep.Protocol),
	}

	b.mu.Lock()
	// OTX rejects duplicates inside one request, and the same IP may be reported again after the cooldown.
	for _, q := range b.batch {
		if q.Indicator == ind.Indicator {
			b.mu.Unlock()
			return
		}
	}
	b.batch = append(b.batch, ind)
	full := len(b.batch) >= b.batchSize
	b.mu.Unlock()

	if full {
		b.flush()
	}
}

// flushLoop makes sure queued entries do not wait indefinitely for the batch to fill up.
func (b *otxBackend) flushLoop() {
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
func (b *otxBackend) stop() {
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
func (b *otxBackend) flush() {
	b.flushMu.Lock()
	defer b.flushMu.Unlock()

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

	logger.WithError(err).WithField("entries", len(batch)).Warn("OTX: submission failed")

	if !retry {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Failed entries are older than anything queued meanwhile, keep them in front.
	b.batch = append(batch, b.batch...)
	if limit := b.batchSize * otxMaxQueueFactor; len(b.batch) > limit {
		dropped := len(b.batch) - limit
		b.batch = b.batch[dropped:]
		logger.WithField("dropped", dropped).Warn("OTX: queue full, oldest entries dropped")
	}
}

// submit creates the pulse (first batch) or adds the batch to the existing pulse. The returned bool tells whether a
// retry later makes sense (network error / 5xx / 429) or not (rejected request, e.g. invalid API key or pulse id).
func (b *otxBackend) submit(batch []otxIndicator) (retry bool, err error) {
	b.mu.Lock()
	pulseID := b.pulseID
	b.mu.Unlock()

	var (
		method = http.MethodPost
		path   = otxCreatePath
		body   []byte
	)

	if pulseID == "" {
		body, err = json.Marshal(otxCreateBody{
			Name:        b.pulseName,
			Description: "Source IPs of SSH/Telnet password guessing observed by an GAS85/ssh-auth-logger honeypot (https://github.com/GAS85/ssh-auth-logger). No credentials are shared.",
			Public:      b.public,
			TLP:         b.tlp,
			Tags:        b.tags,
			References:  []string{otxReferenceURL},
			Indicators:  batch,
		})
	} else {
		var eb otxEditBody
		eb.Indicators.Add = batch
		method, path = http.MethodPatch, otxEditPath+url.PathEscape(pulseID)
		body, err = json.Marshal(eb)
	}
	if err != nil {
		return false, err
	}

	req, err := http.NewRequest(method, b.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-OTX-API-KEY", b.apiKey)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := respBody
		if len(snippet) > 4096 {
			snippet = snippet[:4096]
		}
		retry = resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
		return retry, fmt.Errorf("status %s: %s", resp.Status, snippet)
	}

	if pulseID == "" {
		var created struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(respBody, &created) == nil && created.ID != "" {
			b.mu.Lock()
			b.pulseID = created.ID
			b.mu.Unlock()
			logger.WithField("pulse", created.ID).
				Infof("OTX: pulse created. Set OTX_PULSE_ID=%s to keep using it after a restart", created.ID)
		} else {
			// Submitted, but we cannot append later: the next batch will create another pulse.
			logger.Warn("OTX: pulse created but the response has no id")
		}
	}

	logger.WithFields(logrus.Fields{
		"entries": len(batch),
		"status":  resp.Status,
	}).Info("OTX: indicators submitted")

	return false, nil
}
