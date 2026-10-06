package abuse

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// ── test server ──────────────────────────────────────────────────────────────

type dshieldReq struct {
	method  string
	header  http.Header
	raw     []byte
	payload dshieldPayload
}

type dshieldServer struct {
	*httptest.Server
	mu        sync.Mutex
	status    int
	reqs      []dshieldReq
	onRequest func() // called while handling a request, without the lock held
}

func newDShieldServer(t *testing.T) *dshieldServer {
	t.Helper()
	s := &dshieldServer{status: 200}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var p dshieldPayload
		_ = json.Unmarshal(raw, &p)

		s.mu.Lock()
		s.reqs = append(s.reqs, dshieldReq{r.Method, r.Header.Clone(), raw, p})
		status, hook := s.status, s.onRequest
		s.mu.Unlock()

		if hook != nil {
			hook()
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte("OK 123 Bytes received"))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *dshieldServer) setStatus(code int) {
	s.mu.Lock()
	s.status = code
	s.mu.Unlock()
}

func (s *dshieldServer) requests() []dshieldReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]dshieldReq(nil), s.reqs...)
}

func (s *dshieldServer) totalEntries() int {
	n := 0
	for _, r := range s.requests() {
		n += len(r.payload.Logs)
	}
	return n
}

func newDShieldForTest(endpoint string, mods ...func(*dshieldBackend)) *dshieldBackend {
	b := &dshieldBackend{
		userID:              "12345",
		apiKey:              "secretkey",
		endpoint:            endpoint,
		batchSize:           2,
		flushEvery:          time.Hour,
		reportClearUsername: true,
		reportClearPassword: true,
		httpClient:          &http.Client{Timeout: 5 * time.Second},
	}
	for _, m := range mods {
		m(b)
	}
	return b
}

func entry(user string) dshieldLogEntry {
	return dshieldLogEntry{Timestamp: "2026-01-01T00:00:00.000000Z", SourceIP: "198.51.100.1", User: user}
}

func (b *dshieldBackend) queued() []dshieldLogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]dshieldLogEntry(nil), b.batch...)
}

// ── authentication ───────────────────────────────────────────────────────────

func TestDShield_AuthHeaderKnownAnswer(t *testing.T) {
	// Expected digest computed independently with Python, using the algorithm of Cowrie's output_dshield plugin:
	// hmac.new((nonce+userid).encode(), auth_key.encode(), sha256) -> base64
	b := &dshieldBackend{userID: "12345", apiKey: "secretkey"}
	got := b.authHeaderWithNonce("ADOUf58prEY=")
	want := "ISC-HMAC-SHA256 Credentials=1y5abGdvi8l691fBHtBjHicFThimxHSvZq4JN4Fagz0= Userid=12345 Nonce=ADOUf58prEY="
	if got != want {
		t.Errorf("header =\n  %s\nwant\n  %s", got, want)
	}
}

func TestDShield_AuthHeaderRandomNonce(t *testing.T) {
	b := &dshieldBackend{userID: "777", apiKey: "k3y"}
	re := regexp.MustCompile(`^ISC-HMAC-SHA256 Credentials=(\S+) Userid=777 Nonce=(\S+)$`)

	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		h, err := b.authHeader()
		if err != nil {
			t.Fatal(err)
		}
		m := re.FindStringSubmatch(h)
		if m == nil {
			t.Fatalf("malformed header %q", h)
		}
		raw, err := base64.StdEncoding.DecodeString(m[2])
		if err != nil || len(raw) != 8 {
			t.Fatalf("nonce %q must be base64 of 8 bytes (err=%v, len=%d)", m[2], err, len(raw))
		}
		mac := hmac.New(sha256.New, []byte(m[2]+"777"))
		mac.Write([]byte("k3y"))
		if want := base64.StdEncoding.EncodeToString(mac.Sum(nil)); m[1] != want {
			t.Errorf("signature mismatch for nonce %s", m[2])
		}
		seen[m[2]] = true
	}
	if len(seen) != 20 {
		t.Errorf("nonce reuse detected: only %d distinct nonces in 20 headers", len(seen))
	}
}

func TestDShield_AuthHeaderDependsOnCredentials(t *testing.T) {
	a := (&dshieldBackend{userID: "1", apiKey: "a"}).authHeaderWithNonce("n")
	b := (&dshieldBackend{userID: "1", apiKey: "b"}).authHeaderWithNonce("n")
	c := (&dshieldBackend{userID: "2", apiKey: "a"}).authHeaderWithNonce("n")
	if a == b || a == c {
		t.Error("signature must change with the API key and user id")
	}
	if strings.Contains(a, "Credentials=a ") {
		t.Error("API key must never appear in the header")
	}
}

// ── Sanitize ─────────────────────────────────────────────────────────────────

func TestDShield_Sanitize(t *testing.T) {
	hash := sha1Hex("hunter2")[:8]
	cases := []struct {
		name                      string
		clearUser, clearPW, hashd bool
		wantUser, wantPW          string
	}{
		{"all clear", true, true, false, "root", "hunter2"},
		{"nothing", false, false, false, "", ""},
		{"user only", true, false, false, "root", ""},
		{"password only", false, true, false, "", "hunter2"},
		{"hashed", true, false, true, "root", hash},
		{"hashed beats clear", true, true, true, "root", hash},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newDShieldForTest("", func(b *dshieldBackend) {
				b.reportClearUsername, b.reportClearPassword, b.reportHashedPassword = tc.clearUser, tc.clearPW, tc.hashd
			})
			u, p := b.Sanitize("root", "hunter2")
			if u != tc.wantUser || p != tc.wantPW {
				t.Errorf("got (%q,%q), want (%q,%q)", u, p, tc.wantUser, tc.wantPW)
			}
		})
	}
	b := newDShieldForTest("", func(b *dshieldBackend) { b.reportHashedPassword = true })
	if _, p := b.Sanitize("u", ""); p != "" {
		t.Error("an empty password must stay empty, not become a hash")
	}
	if b.Name() != "DShield" {
		t.Errorf("Name() = %q", b.Name())
	}
}

// ── Report: conversion and batching ──────────────────────────────────────────

func TestDShield_ReportConvertsEntries(t *testing.T) {
	srv := newDShieldServer(t)
	b := newDShieldForTest(srv.URL, func(b *dshieldBackend) { b.batchSize = 1 })

	ts := time.Date(2026, 1, 2, 5, 4, 5, 123456789, time.FixedZone("UTC+2", 2*3600))
	b.Report(Report{
		IP:       "203.0.113.7",
		Protocol: "SSH",
		Creds:    []Credential{{Time: ts, Username: "root", Password: "toor"}},
	})

	reqs := srv.requests()
	if len(reqs) != 1 || len(reqs[0].payload.Logs) != 1 {
		t.Fatalf("requests = %d", len(reqs))
	}

	e := reqs[0].payload.Logs[0]
	if e.Timestamp != "2026-01-02T03:04:05.123456Z" {
		t.Errorf("timestamp = %q (must be UTC, microseconds, trailing Z)", e.Timestamp)
	}
	if e.SourceIP != "203.0.113.7" || e.User != "root" || e.Password != "toor" {
		t.Errorf("entry = %+v", e)
	}
	if e.LastCommand != "" || e.Hassh != "" || e.Banner != "" {
		t.Errorf("fields we don't collect must be empty: %+v", e)
	}
}

func TestDShield_ReportTruncatesLongFields(t *testing.T) {
	srv := newDShieldServer(t)
	b := newDShieldForTest(srv.URL, func(b *dshieldBackend) { b.batchSize = 1 })

	long := strings.Repeat("é", 300) // 600 bytes
	b.Report(Report{IP: "203.0.113.8", Creds: []Credential{{Time: time.Now(), Username: long, Password: long}}})

	e := srv.requests()[0].payload.Logs[0]
	for name, v := range map[string]string{"user": e.User, "password": e.Password} {
		if len(v) > dshieldMaxFieldLen || !utf8.ValidString(v) {
			t.Errorf("%s: %d bytes, valid=%v", name, len(v), utf8.ValidString(v))
		}
		if len(v) == 0 {
			t.Errorf("%s truncated to nothing", name)
		}
	}
}

func TestDShield_ReportWaitsForFullBatch(t *testing.T) {
	srv := newDShieldServer(t)
	b := newDShieldForTest(srv.URL) // batchSize 2

	b.Report(Report{IP: "203.0.113.9", Creds: []Credential{{Time: time.Now(), Username: "a"}}})
	if n := len(srv.requests()); n != 0 {
		t.Fatalf("sent %d requests before the batch was full", n)
	}
	if len(b.queued()) != 1 {
		t.Fatalf("queued = %d, want 1", len(b.queued()))
	}

	b.Report(Report{IP: "203.0.113.10", Creds: []Credential{{Time: time.Now(), Username: "b"}}})
	reqs := srv.requests()
	if len(reqs) != 1 || len(reqs[0].payload.Logs) != 2 {
		t.Fatalf("expected one request with 2 entries, got %d requests", len(reqs))
	}
	if reqs[0].payload.Logs[0].SourceIP == reqs[0].payload.Logs[1].SourceIP {
		t.Error("entries from different IPs should share one batch")
	}
	if len(b.queued()) != 0 {
		t.Error("queue not emptied after successful submission")
	}
}

func TestDShield_ReportWithoutCredentialsStillQueuesNothing(t *testing.T) {
	srv := newDShieldServer(t)
	b := newDShieldForTest(srv.URL)
	b.Report(Report{IP: "203.0.113.11"})
	if len(b.queued()) != 0 || len(srv.requests()) != 0 {
		t.Error("a report without credentials must not queue or send anything")
	}
}

// ── submit: wire format ──────────────────────────────────────────────────────

func TestDShield_SubmitWireFormat(t *testing.T) {
	srv := newDShieldServer(t)
	b := newDShieldForTest(srv.URL)

	userAgent = "wire-test/1.0"
	t.Cleanup(func() { userAgent = "ssh-auth-logger" })

	b.batch = []dshieldLogEntry{entry("root")}
	b.flush()

	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d", len(reqs))
	}
	r := reqs[0]

	if r.method != http.MethodPost {
		t.Errorf("method = %s", r.method)
	}
	if r.header.Get("Content-Type") != "application/json" ||
		r.header.Get("User-Agent") != "wire-test/1.0" ||
		r.header.Get("X-ISC-LogType") != "cowrie" {
		t.Errorf("headers = %v", r.header)
	}

	auth := r.header.Get("X-ISC-Authorization")
	if !strings.HasPrefix(auth, "ISC-HMAC-SHA256 Credentials=") ||
		!strings.Contains(auth, "Userid=12345") {
		t.Errorf("auth header = %q", auth)
	}

	if r.payload.AuthHeader != auth {
		t.Error("authheader in the body must equal the X-ISC-Authorization header")
	}

	if strings.Contains(string(r.raw), "secretkey") ||
		strings.Contains(auth, "secretkey") {
		t.Error("API key must never be transmitted")
	}

	var generic map[string]any
	if err := json.Unmarshal(r.raw, &generic); err != nil {
		t.Fatal(err)
	}

	if len(generic) != 3 || generic["type"] != "cowrie" {
		t.Errorf("top-level keys = %v", generic)
	}

	// Logs is now represented by the new log structure.
	logs, ok := generic["logs"].([]any)
	if !ok {
		t.Fatalf("logs has type %T, want []any", generic["logs"])
	}
	if len(logs) != 1 {
		t.Fatalf("logs has %d entries, want 1", len(logs))
	}

	logEntry, ok := logs[0].(map[string]any)
	if !ok {
		t.Fatalf("log entry has type %T, want object", logs[0])
	}

	keys := map[string]bool{}
	for k := range logEntry {
		keys[k] = true
	}

	for _, want := range []string{
		"timestamp",
		"source_ip",
		"user",
		"password",
		"lastcommand",
		"hassh",
		"banner",
	} {
		if !keys[want] {
			t.Errorf("log entry lacks key %q", want)
		}
	}

	if len(keys) != 7 {
		t.Errorf("log entry has unexpected keys: %v", keys)
	}
}

func TestDShield_SubmitInvalidEndpoint(t *testing.T) {
	b := newDShieldForTest("://not a url")
	retry, err := b.submit([]dshieldLogEntry{entry("x")})
	if err == nil {
		t.Fatal("expected an error")
	}
	if retry {
		t.Error("a malformed endpoint is permanent: retry must be false")
	}
}

// ── flush: status handling, requeue ──────────────────────────────────────────

func TestDShield_FlushStatusHandling(t *testing.T) {
	cases := []struct {
		status  int
		requeue bool
	}{
		{200, false}, {201, false}, {204, false},
		{400, false}, {401, false}, {403, false}, {404, false}, {422, false},
		{429, true},
		{500, true}, {502, true}, {503, true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			hook := captureLogs(t)
			srv := newDShieldServer(t)
			srv.setStatus(tc.status)
			b := newDShieldForTest(srv.URL)
			b.batch = []dshieldLogEntry{entry("a"), entry("b")}

			b.flush()

			if len(srv.requests()) != 1 {
				t.Fatalf("requests = %d, want 1", len(srv.requests()))
			}
			got := len(b.queued())
			if tc.requeue && got != 2 {
				t.Errorf("status %d: queued = %d, want entries re-queued", tc.status, got)
			}
			if !tc.requeue && got != 0 {
				t.Errorf("status %d: queued = %d, want queue empty", tc.status, got)
			}

			ok := tc.status >= 200 && tc.status < 300
			if ok && hook.find("entries submitted") == nil {
				t.Error("missing success log")
			}
			if !ok {
				e := hook.find("submission failed")
				if e == nil {
					t.Fatal("missing failure log")
				}
				errText := fmt.Sprint(e.Data["error"])
				if !strings.Contains(errText, fmt.Sprint(tc.status)) || !strings.Contains(errText, "OK 123 Bytes received") {
					t.Errorf("failure log should carry status and body: %q", errText)
				}
				if e.Data["entries"] != 2 {
					t.Errorf("entries field = %v", e.Data["entries"])
				}
			}
		})
	}
}

func TestDShield_FlushEmptyQueueSendsNothing(t *testing.T) {
	srv := newDShieldServer(t)
	b := newDShieldForTest(srv.URL)
	b.flush()
	if len(srv.requests()) != 0 {
		t.Error("an empty queue must not cause a request")
	}
}

func TestDShield_FlushNetworkErrorRequeues(t *testing.T) {
	hook := captureLogs(t)
	srv := newDShieldServer(t)
	url := srv.URL
	srv.Close() // connection refused from now on

	b := newDShieldForTest(url)
	b.batch = []dshieldLogEntry{entry("a")}
	b.flush()

	if len(b.queued()) != 1 {
		t.Errorf("queued = %d, want entry kept for retry", len(b.queued()))
	}
	if hook.find("submission failed") == nil {
		t.Error("missing failure log")
	}
}

func TestDShield_RequeuedEntriesStayInFrontOfNewOnes(t *testing.T) {
	captureLogs(t)
	srv := newDShieldServer(t)
	srv.setStatus(503)
	b := newDShieldForTest(srv.URL, func(b *dshieldBackend) { b.batchSize = 10 })

	// A new entry arrives while the request is in flight.
	srv.mu.Lock()
	srv.onRequest = func() {
		b.mu.Lock()
		b.batch = append(b.batch, entry("new"))
		b.mu.Unlock()
	}
	srv.mu.Unlock()

	b.batch = []dshieldLogEntry{entry("old1"), entry("old2")}
	b.flush()

	var order []string
	for _, e := range b.queued() {
		order = append(order, e.User)
	}
	if strings.Join(order, ",") != "old1,old2,new" {
		t.Errorf("queue order = %v, want [old1 old2 new]", order)
	}
}

func TestDShield_QueueCapDropsOldest(t *testing.T) {
	hook := captureLogs(t)
	srv := newDShieldServer(t)
	srv.setStatus(500)
	b := newDShieldForTest(srv.URL) // batchSize 2 => limit 2*dshieldMaxQueueFactor

	limit := b.batchSize * dshieldMaxQueueFactor
	total := limit + 3
	for i := 0; i < total; i++ {
		b.batch = append(b.batch, entry(fmt.Sprintf("u%d", i)))
	}
	b.flush()

	q := b.queued()
	if len(q) != limit {
		t.Fatalf("queued = %d, want cap %d", len(q), limit)
	}
	if q[0].User != "u3" || q[len(q)-1].User != fmt.Sprintf("u%d", total-1) {
		t.Errorf("must keep the newest entries: first=%s last=%s", q[0].User, q[len(q)-1].User)
	}
	e := hook.find("queue full")
	if e == nil || e.Data["dropped"] != 3 {
		t.Errorf("queue-full log = %+v", e)
	}
}

func TestDShield_ReportBeyondCapWhileDownStaysBounded(t *testing.T) {
	captureLogs(t)
	srv := newDShieldServer(t)
	srv.setStatus(500)
	b := newDShieldForTest(srv.URL, func(b *dshieldBackend) { b.batchSize = 5 })

	for i := 0; i < 40; i++ {
		b.Report(Report{IP: "203.0.113.20", Creds: []Credential{{Time: time.Now(), Username: fmt.Sprintf("u%d", i)}}})
	}
	if n := len(b.queued()); n > 5*dshieldMaxQueueFactor {
		t.Errorf("queue grew to %d while the API was failing", n)
	}
}

// ── redirects ────────────────────────────────────────────────────────────────

func TestNewDShieldFromEnv_NeverFollowsRedirects(t *testing.T) {
	useEnv(t, "DSHIELD_ENABLED", "true", "DSHIELD_USERID", "1", "DSHIELD_API_KEY", "k")
	captureLogs(t)

	var mu sync.Mutex
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	be, _ := newDShieldFromEnv()
	b := be.(*dshieldBackend)
	t.Cleanup(b.stop)
	b.endpoint = redirector.URL
	b.batch = []dshieldLogEntry{entry("a")}
	b.flush()

	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatal("the redirect was followed: the auth header would be sent to another host")
	}
	if len(b.queued()) != 0 {
		t.Error("a redirect response is a permanent failure and must not be retried forever")
	}
}

// ── debug mode ───────────────────────────────────────────────────────────────

func TestDShield_SuccessLogBodyOnlyInDebug(t *testing.T) {
	for _, debug := range []bool{false, true} {
		t.Run(fmt.Sprintf("debug=%v", debug), func(t *testing.T) {
			hook := captureLogs(t)
			srv := newDShieldServer(t)
			b := newDShieldForTest(srv.URL, func(b *dshieldBackend) { b.debug = debug })
			b.batch = []dshieldLogEntry{entry("a")}
			b.flush()

			e := hook.find("entries submitted")
			if e == nil {
				t.Fatal("missing success log")
			}
			body, has := e.Data["body"]
			if debug && body != "OK 123 Bytes received" {
				t.Errorf("debug mode should log the response body, got %v", body)
			}
			if !debug && has {
				t.Error("response body must not be logged outside debug mode")
			}
			if e.Data["entries"] != 1 {
				t.Errorf("entries = %v", e.Data["entries"])
			}
		})
	}
}

// ── flushLoop ────────────────────────────────────────────────────────────────

func TestDShield_FlushLoopSendsPartialBatches(t *testing.T) {
	captureLogs(t)
	srv := newDShieldServer(t)
	b := newDShieldForTest(srv.URL, func(b *dshieldBackend) {
		b.batchSize = 1000 // never fills
		b.flushEvery = 10 * time.Millisecond
	})
	b.batch = []dshieldLogEntry{entry("lonely")}
	b.done, b.loopDone = make(chan struct{}), make(chan struct{})
	go b.flushLoop()
	t.Cleanup(b.stop)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.totalEntries() == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("flushLoop never submitted the partial batch")
}

// ── concurrency ──────────────────────────────────────────────────────────────

func TestDShield_ConcurrentReportAndFlushLoseNothing(t *testing.T) {
	captureLogs(t)
	srv := newDShieldServer(t)
	b := newDShieldForTest(srv.URL, func(b *dshieldBackend) { b.batchSize = 7 })

	const workers, perWorker = 20, 25
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				b.Report(Report{IP: "203.0.113.30", Creds: []Credential{{Time: time.Now(), Username: fmt.Sprintf("w%d-%d", w, i)}}})
				if i%10 == 0 {
					b.flush()
				}
			}
		}(w)
	}
	wg.Wait()
	b.flush()

	if got := srv.totalEntries(); got != workers*perWorker {
		t.Errorf("server received %d entries, want %d", got, workers*perWorker)
	}
	if len(b.queued()) != 0 {
		t.Error("entries left in the queue")
	}
}

// ── Constructor ──────────────────────────────────────────────────────────────

func TestNewDShieldFromEnv_DisabledByDefault(t *testing.T) {
	useEnv(t)
	b, fields := newDShieldFromEnv()
	if b != nil || fields != nil {
		t.Fatalf("expected (nil, nil), got (%v, %v)", b, fields)
	}
}

func TestNewDShieldFromEnv_Defaults(t *testing.T) {
	useEnv(t, "DSHIELD_ENABLED", "true", "DSHIELD_USERID", "42", "DSHIELD_API_KEY", "TOPSECRET")

	be, fields := newDShieldFromEnv()
	b := be.(*dshieldBackend)
	t.Cleanup(b.stop)

	if b.userID != "42" || b.apiKey != "TOPSECRET" {
		t.Error("credentials not read")
	}
	if b.batchSize != 50 || b.flushEvery != 10*time.Minute {
		t.Errorf("batch defaults = %d / %v", b.batchSize, b.flushEvery)
	}
	if !b.reportClearUsername || !b.reportClearPassword || b.reportHashedPassword {
		t.Errorf("privacy defaults: user=%v pw=%v hashed=%v",
			b.reportClearUsername, b.reportClearPassword, b.reportHashedPassword)
	}
	if b.debug || b.endpoint != dshieldSubmitURL {
		t.Errorf("production endpoint expected, got debug=%v endpoint=%s", b.debug, b.endpoint)
	}
	if b.httpClient.Timeout != 10*time.Second || b.httpClient.CheckRedirect == nil {
		t.Error("http client must have a timeout and block redirects")
	}

	dshieldFields, ok := fields["dshield"].(logrus.Fields)
	if !ok {
		t.Fatalf("fields[dshield] = %T, want logrus.Fields", fields["dshield"])
	}

	if dshieldFields["DSHIELD_USERID"] != "42" ||
		dshieldFields["DSHIELD_BATCH_SIZE"] != 50 ||
		dshieldFields["DSHIELD_BATCH_INTERVAL"] != "10m0s" {
		t.Errorf("dshield fields = %v", dshieldFields)
	}

	if dshieldFields["DSHIELD_DEBUG"] != false ||
		dshieldFields["DSHIELD_ENABLED"] != true ||
		dshieldFields["DSHIELD_REPORT_CLEAR_USERNAME"] != true ||
		dshieldFields["DSHIELD_REPORT_CLEAR_PASSWORD"] != true ||
		dshieldFields["DSHIELD_REPORT_HASHED_PASSWORD"] != false {
		t.Errorf("dshield fields = %v", dshieldFields)
	}

	for k, v := range dshieldFields {
		if s, ok := v.(string); ok &&
			(s == "TOPSECRET" || s == "42") {
			if s == "TOPSECRET" {
				t.Errorf("field %s leaks the API key", k)
			}
		}
	}
}

func TestNewDShieldFromEnv_MissingCredentialsAreFatal(t *testing.T) {
	cases := [][]string{
		{"DSHIELD_ENABLED", "true"},
		{"DSHIELD_ENABLED", "true", "DSHIELD_USERID", "1"},
		{"DSHIELD_ENABLED", "true", "DSHIELD_API_KEY", "k"},
	}

	for _, kv := range cases {
		useEnv(t, kv...)
		msg := expectFatal(t, func() { newDShieldFromEnv() })
		if !strings.Contains(msg, "DSHIELD_USERID") ||
			!strings.Contains(msg, "DSHIELD_API_KEY") {
			t.Errorf("message %q", msg)
		}
	}
}

func TestNewDShieldFromEnv_DebugUsesDevEndpoint(t *testing.T) {
	useEnv(t,
		"DSHIELD_ENABLED", "true",
		"DSHIELD_USERID", "1",
		"DSHIELD_API_KEY", "k",
		"DSHIELD_DEBUG", "true",
	)

	be, fields := newDShieldFromEnv()
	b := be.(*dshieldBackend)
	t.Cleanup(b.stop)

	if !b.debug || b.endpoint != dshieldDebugSubmitURL {
		t.Errorf("debug=%v endpoint=%s", b.debug, b.endpoint)
	}

	dshieldFields, ok := fields["dshield"].(logrus.Fields)
	if !ok {
		t.Fatalf("fields[dshield] = %T, want logrus.Fields", fields["dshield"])
	}

	if dshieldFields["DSHIELD_DEBUG"] != true {
		t.Errorf("DSHIELD_DEBUG = %v, want true", dshieldFields["DSHIELD_DEBUG"])
	}

	if dshieldFields["DSHIELD_ENABLED"] != true {
		t.Errorf("DSHIELD_ENABLED = %v, want true", dshieldFields["DSHIELD_ENABLED"])
	}
}

func TestNewDShieldFromEnv_Overrides(t *testing.T) {
	useEnv(t, "DSHIELD_ENABLED", "true", "DSHIELD_USERID", "1", "DSHIELD_API_KEY", "k",
		"DSHIELD_BATCH_SIZE", "5", "DSHIELD_BATCH_INTERVAL", "30s",
		"DSHIELD_REPORT_CLEAR_USERNAME", "false", "DSHIELD_REPORT_CLEAR_PASSWORD", "false")
	be, _ := newDShieldFromEnv()
	b := be.(*dshieldBackend)
	t.Cleanup(b.stop)
	if b.batchSize != 5 || b.flushEvery != 30*time.Second || b.reportClearUsername || b.reportClearPassword {
		t.Errorf("overrides not applied: %+v", b)
	}
}

func TestNewDShieldFromEnv_HashedOverridesClearPassword(t *testing.T) {
	useEnv(t,
		"DSHIELD_ENABLED", "true",
		"DSHIELD_USERID", "1",
		"DSHIELD_API_KEY", "k",
		"DSHIELD_REPORT_HASHED_PASSWORD", "true",
	)

	be, fields := newDShieldFromEnv()
	b := be.(*dshieldBackend)
	t.Cleanup(b.stop)

	if b.reportClearPassword || !b.reportHashedPassword {
		t.Fatalf(
			"hashed must override clear: clear=%v hashed=%v",
			b.reportClearPassword,
			b.reportHashedPassword,
		)
	}

	dshieldFields, ok := fields["dshield"].(logrus.Fields)
	if !ok {
		t.Fatalf("fields[dshield] = %T, want logrus.Fields", fields["dshield"])
	}

	if dshieldFields["DSHIELD_REPORT_CLEAR_PASSWORD"] != false {
		t.Errorf(
			"startup log must show the effective value, got %v",
			dshieldFields["DSHIELD_REPORT_CLEAR_PASSWORD"],
		)
	}

	if dshieldFields["DSHIELD_REPORT_HASHED_PASSWORD"] != true {
		t.Errorf(
			"startup log must show the effective value, got %v",
			dshieldFields["DSHIELD_REPORT_HASHED_PASSWORD"],
		)
	}

	if _, p := b.Sanitize("u", "secret"); p == "secret" {
		t.Error("cleartext password would be transmitted")
	}
}

func TestNewDShieldFromEnv_InvalidConfigIsFatal(t *testing.T) {
	base := []string{"DSHIELD_ENABLED", "true", "DSHIELD_USERID", "1", "DSHIELD_API_KEY", "k"}
	cases := []struct{ key, value string }{
		{"DSHIELD_BATCH_SIZE", "abc"},
		{"DSHIELD_BATCH_SIZE", "0"},
		{"DSHIELD_BATCH_SIZE", "-1"},
		{"DSHIELD_BATCH_INTERVAL", "often"},
		{"DSHIELD_BATCH_INTERVAL", "0s"},
		{"DSHIELD_BATCH_INTERVAL", "-1m"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			useEnv(t, append(append([]string{}, base...), tc.key, tc.value)...)
			msg := expectFatal(t, func() { newDShieldFromEnv() })
			if !strings.Contains(msg, tc.key) {
				t.Errorf("message %q does not name %s", msg, tc.key)
			}
		})
	}
}

func TestDShield_StopEndsFlushLoopAndIsIdempotent(t *testing.T) {
	useEnv(t, "DSHIELD_ENABLED", "true", "DSHIELD_USERID", "1", "DSHIELD_API_KEY", "k")
	be, _ := newDShieldFromEnv()
	b := be.(*dshieldBackend)

	finished := make(chan struct{})
	go func() { b.stop(); b.stop(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() did not return: flushLoop is still running")
	}
}

// ── source_ip representation ─────────────────────────────────────────────────

func TestDShield_SourceIPIsAlwaysADottedOrColonStringNeverANumber(t *testing.T) {
	srv := newDShieldServer(t)
	b := newDShieldForTest(srv.URL, func(b *dshieldBackend) {
		b.batchSize = 1
	})

	for _, ip := range []string{
		"77.91.65.68",
		"192.0.2.1",
		"2001:db8::1",
	} {
		b.Report(Report{
			IP:    ip,
			Creds: []Credential{{Time: time.Now(), Username: "root"}},
		})
	}

	reqs := srv.requests()
	if len(reqs) != 3 {
		t.Fatalf("requests = %d", len(reqs))
	}

	for i, ip := range []string{
		"77.91.65.68",
		"192.0.2.1",
		"2001:db8::1",
	} {
		want := fmt.Sprintf(`"source_ip":%q`, ip)
		if !strings.Contains(string(reqs[i].raw), want) {
			t.Errorf("raw body lacks %s: %s", want, reqs[i].raw)
		}
	}
}

func TestDShield_DebugLogsPayloadButNeverTheSignature(t *testing.T) {
	for _, debug := range []bool{false, true} {
		t.Run(fmt.Sprintf("debug=%v", debug), func(t *testing.T) {
			hook := captureLogs(t)
			srv := newDShieldServer(t)
			b := newDShieldForTest(srv.URL, func(b *dshieldBackend) { b.debug = debug })
			b.batch = []dshieldLogEntry{{Timestamp: "2026-01-01T00:00:00.000000Z", SourceIP: "77.91.65.68", User: "root"}}
			b.flush()

			e := hook.find("submitting payload")
			if !debug {
				if e != nil {
					t.Error("payload must only be logged in debug mode")
				}
				return
			}
			if e == nil {
				t.Fatal("debug mode should log the payload")
			}
			payload := fmt.Sprint(e.Data["payload"])
			if !strings.Contains(payload, `"source_ip":"77.91.65.68"`) {
				t.Errorf("payload log lacks the source IP: %s", payload)
			}
			sent := srv.requests()[0].header.Get("X-ISC-Authorization")
			digest := regexp.MustCompile(`Credentials=(\S+)`).FindStringSubmatch(sent)[1]
			if strings.Contains(payload, digest) || strings.Contains(payload, "secretkey") {
				t.Error("payload log leaks the signature or API key")
			}
		})
	}
}
