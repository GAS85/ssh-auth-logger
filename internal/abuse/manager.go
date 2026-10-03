package abuse

import (
	"crypto/sha1"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/sirupsen/logrus"
)

// ---------------------------------------------------------------------------
// Abuse reporting core
//
// The core is backend-agnostic: it counts failed authentication attempts per
// source IP, applies the shared ABUSE_* thresholds / cooldown / cleanup, and
// once an IP crosses the threshold hands a report to every enabled backend.
//
// To add another reporting service:
//  1. create a new file with a type implementing Backend,
//  2. add a constructor `func newXxxFromEnv() (Backend, logrus.Fields)`
//     that returns (nil, nil) when the service is disabled,
//  3. append that constructor to abuseBackendFactories below.
// ---------------------------------------------------------------------------

// Shared settings (ABUSE_*), identical for every backend.
var (
	abuseAttempts        int           // ABUSE_REPORT_ATTEMPTS: failures per IP before a report is sent
	abuseReportInterval  time.Duration // ABUSE_REPORT_INTERVAL: cooldown per IP after a report
	abuseCleanupInterval time.Duration // ABUSE_CLEANUP_INTERVAL: how often stale IP state is purged
	abuseStateExpiry     time.Duration // ABUSE_STATE_EXPIRY: IP state not seen for this long is dropped
)

// maxCredsPerWindow bounds how many distinct credential pairs are remembered per IP and backend between two reports, so a noisy attacker cannot grow memory without limit.
const maxCredsPerWindow = 100

// Dependencies injected by the caller through Setup. The package cannot import package main, so these replace main's logger, getEnvWithDefault, appName and version.
var (
	logger    = logrus.NewEntry(logrus.StandardLogger())
	getenv    = func(name, def string) string { return def }
	userAgent = "ssh-auth-logger"
)

// Options are the dependencies Setup needs from the application.
type Options struct {
	Logger    *logrus.Entry                 // application logger (keeps its common fields)
	Getenv    func(name, def string) string // returns env var value or def if unset
	UserAgent string                        // e.g. "ssh-auth-logger/1.2.3"
}

// abuseBackendFactories lists every supported reporting service.
// Each factory returns (nil, nil) if its service is disabled.
var abuseBackendFactories = []func() (Backend, logrus.Fields){
	newAbuseIPDBFromEnv,
	newDShieldFromEnv,
	newOTXFromEnv,
}

// Credential is one observed login attempt, already filtered by the backend's privacy settings.
type Credential struct {
	Time     time.Time
	Username string
	Password string
}

// Report is what a backend receives once an IP has reached the threshold.
type Report struct {
	IP       string
	Protocol string // "SSH" or "Telnet"
	Creds    []Credential
}

// Backend is implemented by every reporting service.
type Backend interface {
	// Name is used in log messages.
	Name() string

	// Sanitize returns the username/password this backend is allowed to keep and transmit (empty strings if it must not). It is called for every failed attempt, so nothing a backend does not want is ever retained in memory.
	Sanitize(username, password string) (string, string)

	// Report delivers one report. The core calls it in its own goroutine, so it may block on network I/O without affecting authentication handling.
	Report(rep Report)
}

// abuseIPState contains reporting state for one source IP.
type abuseIPState struct {
	attempts     int
	lastReported time.Time
	lastSeen     time.Time
	// creds[i] holds the credentials collected for backends[i].
	creds [][]Credential
}

// Manager tracks authentication failures per source IP and reports abusive IPs to all enabled backends once the configured threshold has been reached.
type Manager struct {
	mu sync.Mutex

	backends []Backend

	attemptsLimit int
	reportEvery   time.Duration
	cleanupEvery  time.Duration
	stateExpiry   time.Duration

	ips map[string]*abuseIPState

	done     chan struct{} // closed by Stop
	loopDone chan struct{} // closed when cleanupLoop has exited (nil if no loop was started)
	stopOnce sync.Once
}

// NewManager creates a Manager reporting to the given backends. Most callers should use Setup, which builds the backends from the environment. NewManager is exported so tests can inject their own Backend.
func NewManager(
	backends []Backend,
	attemptsLimit int,
	reportEvery time.Duration,
	cleanupEvery time.Duration,
	stateExpiry time.Duration,
) *Manager {
	m := &Manager{
		backends:      backends,
		attemptsLimit: attemptsLimit,
		reportEvery:   reportEvery,
		cleanupEvery:  cleanupEvery,
		stateExpiry:   stateExpiry,
		ips:           make(map[string]*abuseIPState),
		done:          make(chan struct{}),
	}

	if len(backends) > 0 {
		m.loopDone = make(chan struct{})
		go m.cleanupLoop()
	}

	return m
}

// Stop ends the background cleanup goroutine and waits for it to exit.
// The Manager normally lives for the whole process, so calling Stop is optional; it exists for graceful shutdown and for tests. RecordFailure keeps working afterwards.
func (m *Manager) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		close(m.done)
		if m.loopDone != nil {
			<-m.loopDone
		}
	})
}

// RecordFailure records a failed authentication attempt.
// Once the configured number of attempts has been reached, the IP is reported asynchronously to every enabled backend.
// Returns true if this call caused a report to be scheduled.
func (m *Manager) RecordFailure(ip, protocol, username, password string) bool {
	// A nil Manager (Setup never called) is a harmless no-op.
	if m == nil || len(m.backends) == 0 {
		return false
	}

	if net.ParseIP(ip) == nil {
		logger.WithField("ip", ip).Warn("Abuse: invalid IP address")
		return false
	}

	now := time.Now()

	m.mu.Lock()

	state, exists := m.ips[ip]
	if !exists {
		state = &abuseIPState{creds: make([][]Credential, len(m.backends))}
		m.ips[ip] = state
	}

	state.lastSeen = now

	// Each backend decides what it is willing to retain (clear / hashed / nothing).
	for i, b := range m.backends {
		u, p := b.Sanitize(username, password)
		state.creds[i] = addCredential(state.creds[i], Credential{Time: now, Username: u, Password: p})
	}

	// If this IP has already been reported recently, don't accumulate another threshold during the cooldown period.
	if !state.lastReported.IsZero() && now.Sub(state.lastReported) < m.reportEvery {
		m.mu.Unlock()
		return false
	}

	state.attempts++

	if state.attempts < m.attemptsLimit {
		m.mu.Unlock()
		return false
	}

	// Copy data before releasing the mutex, then reset it for the next window.
	snapshots := make([][]Credential, len(m.backends))
	for i := range m.backends {
		snapshots[i] = append([]Credential(nil), state.creds[i]...)
		state.creds[i] = nil
	}

	// Mark the IP as reported BEFORE starting the goroutines.
	// If several authentication attempts arrive concurrently, only one of them should schedule a report.
	state.lastReported = now
	state.attempts = 0

	m.mu.Unlock()

	names := make([]string, len(m.backends))
	for i, b := range m.backends {
		names[i] = b.Name()
	}

	logger.WithFields(logrus.Fields{
		"ip":       ip,
		"protocol": protocol,
		"attempts": m.attemptsLimit,
		"backends": strings.Join(names, ","),
	}).Infof("Abuse: report threshold reached for %s. Report IP.", ip)

	for i, b := range m.backends {
		go b.Report(Report{IP: ip, Protocol: protocol, Creds: snapshots[i]})
	}

	return true
}

// addCredential appends c unless the same username/password pair is already present or the per-window cap has been reached.
func addCredential(list []Credential, c Credential) []Credential {
	for _, existing := range list {
		if existing.Username == c.Username && existing.Password == c.Password {
			return list
		}
	}
	if len(list) >= maxCredsPerWindow {
		return list
	}
	return append(list, c)
}

// cleanupLoop periodically purges state of IPs that went quiet.
func (m *Manager) cleanupLoop() {
	defer close(m.loopDone)

	ticker := time.NewTicker(m.cleanupEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanup()
		case <-m.done:
			return
		}
	}
}

// cleanup removes IPs that have not been seen for the configured state-expiry period.
func (m *Manager) cleanup() {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	removed := 0

	for ip, state := range m.ips {
		if now.Sub(state.lastSeen) > m.stateExpiry {
			delete(m.ips, ip)
			removed++
		}
	}

	if removed > 0 {
		logger.WithFields(logrus.Fields{
			"removed":   removed,
			"remaining": len(m.ips),
		}).Debug("Abuse state cleanup completed")
	}
}

// Setup reads the shared ABUSE_* settings, builds every enabled backend and returns the Manager the SSH and Telnet handlers report to.
// It also returns the fields to show in the startup log (empty if nothing is enabled).
func Setup(opts Options) (*Manager, logrus.Fields) {
	if opts.Logger != nil {
		logger = opts.Logger
	}
	if opts.Getenv != nil {
		getenv = opts.Getenv
	}
	if opts.UserAgent != "" {
		userAgent = opts.UserAgent
	}

	var err error

	abuseAttempts, err = strconv.Atoi(getenv("ABUSE_REPORT_ATTEMPTS", "10"))
	if err != nil || abuseAttempts <= 0 {
		logrus.Fatal("Invalid ABUSE_REPORT_ATTEMPTS environment variable")
	}

	// AbuseIPDB allows one report per IP every 15 minutes: https://www.abuseipdb.com/api.html
	abuseReportInterval, err = time.ParseDuration(getenv("ABUSE_REPORT_INTERVAL", "15m"))
	if err != nil || abuseReportInterval <= 0 {
		logrus.Fatal("Invalid ABUSE_REPORT_INTERVAL environment variable")
	}

	abuseCleanupInterval, err = time.ParseDuration(getenv("ABUSE_CLEANUP_INTERVAL", "30m"))
	if err != nil || abuseCleanupInterval <= 0 {
		logrus.Fatal("Invalid ABUSE_CLEANUP_INTERVAL environment variable")
	}

	abuseStateExpiry, err = time.ParseDuration(getenv("ABUSE_STATE_EXPIRY", "2h"))
	if err != nil || abuseStateExpiry <= 0 {
		logrus.Fatal("Invalid ABUSE_STATE_EXPIRY environment variable")
	}

	var backends []Backend
	fields := logrus.Fields{}

	for _, factory := range abuseBackendFactories {
		b, f := factory()
		if b == nil {
			continue
		}
		backends = append(backends, b)
		for k, v := range f {
			fields[k] = v
		}
	}

	manager := NewManager(
		backends,
		abuseAttempts,
		abuseReportInterval,
		abuseCleanupInterval,
		abuseStateExpiry,
	)

	if len(backends) > 0 {
		fields["ABUSE_REPORT_ATTEMPTS"] = abuseAttempts
		fields["ABUSE_REPORT_INTERVAL"] = abuseReportInterval.String()
		fields["ABUSE_CLEANUP_INTERVAL"] = abuseCleanupInterval.String()
		fields["ABUSE_STATE_EXPIRY"] = abuseStateExpiry.String()
	}

	return manager, fields
}

// envBool reads a boolean environment variable ("1", "true" or "yes" means true).
func envBool(name, def string) bool {
	v := getenv(name, def)
	return v == "1" || v == "true" || v == "yes"
}

// truncateUTF8 truncates s to at most maxBytes bytes without splitting a multi-byte rune in half.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	b := s[:maxBytes]
	for len(b) > 0 && !utf8.ValidString(b) {
		b = b[:len(b)-1]
	}
	return b
}

// sha1Hex returns the hex-encoded SHA-1 digest of s.
// SHA-1 is used here only to avoid publishing cleartext credentials to a public database, not as a secure password hash
func sha1Hex(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}

	return append(values, value)
}