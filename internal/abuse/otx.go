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
	"unicode/utf8"

	"github.com/GAS85/ssh-auth-logger/internal/startup"
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

	// OTX accepts pulse names of 5 to 200 characters and answers 400 otherwise.
	otxMinNameLen = 5
	otxMaxNameLen = 200

	// Title and Description are limited to 1024, so common limiter used
	otxMaxCommentLen = 1024
)

// otxIndicator is one entry of a pulse.
type otxIndicator struct {
	Indicator   string `json:"indicator"`
	Type        string `json:"type"` // "IPv4" or "IPv6"
	Role        string `json:"role,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`

	// Credentials seen for this IP while it waits in the queue, already filtered by the report settings. They are not sent as fields: they are rendered into Description.
	usernames  []string
	passwords  []string
	publicKeys []string // fingerprints of offered SSH public keys
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
// By default no credentials are collected: a pulse is (by default) public. Usernames and passwords (hashed, or in clear text) can be added to the indicator description with OTX_REPORT_*, which also restricts the TLP of the pulse.
type otxBackend struct {
	apiKey  string
	baseURL string

	pulseName string
	public    bool
	tlp       string
	tags      []string
	role      string

	// What may be shared in the description of an indicator (OTX_REPORT_*). Nothing by default.
	reportClearUsername  bool
	reportClearPassword  bool
	reportHashedPassword bool

	batchSize  int
	flushEvery time.Duration
	// flushEveryStr is OTX_BATCH_INTERVAL as the user wrote it (e.g. "1h"), used in the pulse description.
	flushEveryStr string

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

	flushEveryStr := getenv("OTX_BATCH_INTERVAL", "1h")
	flushEvery, err := time.ParseDuration(flushEveryStr)
	if err != nil || flushEvery <= 0 {
		logrus.Fatal("Invalid OTX_BATCH_INTERVAL environment variable")
	}

	public := envBool("OTX_PUBLIC", "true")

	// What is shared besides the IP. As for AbuseIPDB, ..._HASHED_PASSWORD takes precedence over ..._CLEAR_PASSWORD, so cleartext passwords are never collected or sent if both are set.
	clearUsername := envBool("OTX_REPORT_CLEAR_USERNAME", "false")
	hashedPassword := envBool("OTX_REPORT_HASHED_PASSWORD", "false")
	clearPassword := envBool("OTX_REPORT_CLEAR_PASSWORD", "false") && !hashedPassword

	// Pulses are read by others: the more is shared, the more restricted the pulse has to be.
	//   nothing shared:                   white (default) or higher
	//   usernames / hashed passwords:     not white; green is the default
	//   cleartext passwords:              red only
	tlp := strings.ToLower(getenv("OTX_TLP", ""))
	if tlp == "" {
		switch {
		case clearPassword:
			tlp = "red"
		case clearUsername || hashedPassword:
			tlp = "green"
		default:
			tlp = "white"
		}
	}
	switch tlp {
	case "white", "green", "amber", "red":
	default:
		logrus.Fatal("Invalid OTX_TLP environment variable (use white, green, amber or red)")
	}
	if (tlp == "amber" || tlp == "red") && public {
		// OTX rejects public pulses with these TLP values.
		logrus.Fatal("Invalid OTX_TLP environment variable: amber and red pulses must be private (set OTX_PUBLIC=false)")
	}
	if clearPassword && tlp != "red" {
		logrus.Fatal("Invalid OTX_TLP environment variable: with OTX_REPORT_CLEAR_PASSWORD only red is allowed (and OTX_PUBLIC=false)")
	}
	if (clearUsername || hashedPassword) && tlp == "white" {
		logrus.Fatal("Invalid OTX_TLP environment variable: white is not allowed with OTX_REPORT_CLEAR_USERNAME or OTX_REPORT_HASHED_PASSWORD (use green or higher)")
	}

	pulseName := getenv("OTX_PULSE_NAME", otxDefaultPulseName)
	pulseID := getenv("OTX_PULSE_ID", "")
	// The name is only sent when a new pulse is created. With OTX_PULSE_ID the existing pulse is edited and its name is never touched, so it is not checked then.
	if n := utf8.RuneCountInString(pulseName); pulseID == "" && (n < otxMinNameLen || n > otxMaxNameLen) {
		logrus.Fatalf("Invalid OTX_PULSE_NAME environment variable: OTX requires %d-%d characters, got %d", otxMinNameLen, otxMaxNameLen, n)
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

		pulseName: pulseName,
		pulseID:   pulseID,
		public:    public,
		tlp:       tlp,
		tags:      tags,
		// Optional OTX indicator role (e.g. "scanning_host"). An unknown role is rejected by the API.
		role: getenv("OTX_INDICATOR_ROLE", "bruteforce"),

		reportClearUsername:  clearUsername,
		reportClearPassword:  clearPassword,
		reportHashedPassword: hashedPassword,

		batchSize:     batchSize,
		flushEvery:    flushEvery,
		flushEveryStr: flushEveryStr,

		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			// The API key header must never follow a redirect to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}

	b.done = make(chan struct{})
	b.loopDone = make(chan struct{})
	go b.flushLoop()

	// Build static part for startup output
	otxFields := logrus.Fields{
		"OTX_ENABLED": true,
		"OTX_TLP":     b.tlp,
	}
	// Only displayed when different from defaults
	startup.AddIfNotDefault(otxFields, "OTX_PULSE_ID", b.pulseID, "")
	startup.AddIfNotDefault(otxFields, "OTX_PULSE_NAME", b.pulseName, otxDefaultPulseName)
	startup.AddIfNotDefault(otxFields, "OTX_PUBLIC", b.public, true)
	startup.AddIfNotDefault(otxFields, "OTX_TAGS", strings.Join(b.tags, ","), "honeypot,ssh,telnet,brute-force")
	startup.AddIfNotDefault(otxFields, "OTX_INDICATOR_ROLE", b.role, "bruteforce")
	startup.AddIfNotDefault(otxFields, "OTX_BATCH_SIZE", b.batchSize, 25)
	startup.AddIfNotDefault(otxFields, "OTX_BATCH_INTERVAL", flushEveryStr, "1h")
	startup.AddIfNotDefault(otxFields, "OTX_REPORT_CLEAR_USERNAME", b.reportClearUsername, false)
	startup.AddIfNotDefault(otxFields, "OTX_REPORT_CLEAR_PASSWORD", b.reportClearPassword, false)
	startup.AddIfNotDefault(otxFields, "OTX_REPORT_HASHED_PASSWORD", b.reportHashedPassword, false)

	return b, logrus.Fields{
		"otx": otxFields,
	}
}

func (b *otxBackend) Name() string { return "OTX" }

// sharesPublicKeys tells whether public key fingerprints are added to the indicators: only together with passwords (hashed or in clear text), as in the AbuseIPDB comment they are an addition to the password information.
func (b *otxBackend) sharesPublicKeys() bool { return b.reportClearPassword || b.reportHashedPassword }

// ReportsPublicKeys implements PublicKeyReporter: public keys are public, so their fingerprints are reported whenever passwords are, hashed or in clear text.
func (b *otxBackend) ReportsPublicKeys() bool { return b.sharesPublicKeys() }

// Sanitize keeps usernames / passwords only if explicitly enabled, exactly like AbuseIPDB. Hashed passwords are cut to the first 8 symbols, as a full SHA1 is easy to revert.
func (b *otxBackend) Sanitize(username, password string) (string, string) {
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

// describe renders the credentials of an indicator as its description, empty if nothing may be shared.
func (b *otxBackend) describe(ind otxIndicator) string {
	var parts []string

	if b.reportClearUsername && len(ind.usernames) > 0 {
		parts = append(parts, fmt.Sprintf("usernames=%q", ind.usernames))
	}

	if (b.reportClearPassword || b.reportHashedPassword) && len(ind.passwords) > 0 {
		field := "passwords"
		if b.reportHashedPassword {
			field = "passwords sha1 prefix"
		}
		parts = append(parts, fmt.Sprintf("%s=%q", field, ind.passwords))
	}

	if b.sharesPublicKeys() && len(ind.publicKeys) > 0 {
		parts = append(parts, fmt.Sprintf("public key fingerprints=%q", ind.publicKeys))
	}

	return truncateUTF8(strings.Join(parts, "; "), otxMaxCommentLen)
}

// batchInterval is the flush interval for the pulse description: OTX_BATCH_INTERVAL as configured, or the parsed duration if only that is set.
func (b *otxBackend) batchInterval() string {
	if b.flushEveryStr != "" {
		return b.flushEveryStr
	}
	return b.flushEvery.String()
}

// pulseDescription is the description of a new pulse. It says that no credentials are shared only if that is true.
func (b *otxBackend) pulseDescription() string {
	d := "Source IPs of SSH/Telnet password guessing observed by a GAS85/ssh-auth-logger honeypot (" + otxReferenceURL + "). New indicators are added in batches, about every " + b.batchInterval() + ", or sooner when a batch fills up. The same IP may be added again in a later update."

	var shared []string
	if b.reportClearUsername {
		shared = append(shared, "usernames")
	}
	if b.reportHashedPassword {
		shared = append(shared, "the first 8 characters of the SHA-1 hash of passwords")
	} else if b.reportClearPassword {
		shared = append(shared, "passwords in clear text")
	}

	if b.sharesPublicKeys() {
		shared = append(shared, "fingerprints of public keys")
	}

	if len(shared) == 0 {
		return d + " No credentials are shared."
	}
	return d + " The indicator descriptions include: " + strings.Join(shared, ", ") + "."
}

// limitIndicators returns a copy of batch in which Title and Description fit the OTX limits.
func limitIndicators(batch []otxIndicator) []otxIndicator {
	out := make([]otxIndicator, len(batch))
	for i, ind := range batch {
		ind.Title = truncateUTF8(ind.Title, otxMaxCommentLen)
		ind.Description = truncateUTF8(ind.Description, otxMaxCommentLen)
		out[i] = ind
	}
	return out
}

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
		Indicator: rep.IP,
		Type:      typ,
		Role:      b.role,
		Title:     truncateUTF8(fmt.Sprintf("%s authentication brute-force attempts against a honeypot", rep.Protocol), otxMaxCommentLen),
	}

	// The credentials were already filtered by Sanitize; the settings are checked again, so nothing is ever shared by accident.
	for _, c := range rep.Creds {
		if b.reportClearUsername && c.Username != "" {
			ind.usernames = appendUnique(ind.usernames, c.Username)
		}
		if (b.reportClearPassword || b.reportHashedPassword) && c.Password != "" {
			ind.passwords = appendUnique(ind.passwords, c.Password)
		}
		if b.sharesPublicKeys() && c.PublicKey != "" {
			ind.publicKeys = appendUnique(ind.publicKeys, c.PublicKey)
		}
	}
	ind.Description = b.describe(ind)

	b.mu.Lock()
	// OTX rejects duplicates inside one request, and the same IP may be reported again after the cooldown. The IP stays queued once, with the credentials of all its reports.
	for i := range b.batch {
		if b.batch[i].Indicator != ind.Indicator {
			continue
		}
		q := &b.batch[i]
		for _, u := range ind.usernames {
			q.usernames = appendUnique(q.usernames, u)
		}
		for _, p := range ind.passwords {
			q.passwords = appendUnique(q.passwords, p)
		}
		for _, k := range ind.publicKeys {
			q.publicKeys = appendUnique(q.publicKeys, k)
		}
		q.Description = b.describe(*q)
		b.mu.Unlock()
		return
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

// Flush submits everything that is queued, without waiting for the batch to fill up or the interval to pass. The Manager calls it on shutdown. If the API cannot be reached the entries stay queued, but the process is about to exit, so they are lost.
func (b *otxBackend) Flush() { b.flush() }

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

	// Title and Description are checked right before sending, whatever put the entries in the queue.
	batch = limitIndicators(batch)

	var (
		method = http.MethodPost
		path   = otxCreatePath
		body   []byte
	)

	if pulseID == "" {
		body, err = json.Marshal(otxCreateBody{
			Name:        b.pulseName,
			Description: truncateUTF8(b.pulseDescription(), otxMaxCommentLen),
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
