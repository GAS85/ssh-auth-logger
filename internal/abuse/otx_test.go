package abuse

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── test server ──────────────────────────────────────────────────────────────

type otxReq struct {
	method string
	path   string
	header http.Header
	raw    []byte
}

func (r otxReq) create(t *testing.T) otxCreateBody {
	t.Helper()
	var b otxCreateBody
	if err := json.Unmarshal(r.raw, &b); err != nil {
		t.Fatalf("invalid create body: %v\n%s", err, r.raw)
	}
	return b
}

func (r otxReq) edit(t *testing.T) otxEditBody {
	t.Helper()
	var b otxEditBody
	if err := json.Unmarshal(r.raw, &b); err != nil {
		t.Fatalf("invalid edit body: %v\n%s", err, r.raw)
	}
	return b
}

type otxServer struct {
	*httptest.Server
	mu     sync.Mutex
	status int
	reply  string // response body
	reqs   []otxReq

	onRequest func() // called while handling a request, without the lock held
}

func newOTXServer(t *testing.T) *otxServer {
	t.Helper()
	s := &otxServer{status: 200, reply: `{"id":"pulse123"}`}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.reqs = append(s.reqs, otxReq{r.Method, r.URL.Path, r.Header.Clone(), raw})
		status, reply, hook := s.status, s.reply, s.onRequest
		s.mu.Unlock()
		if hook != nil {
			hook()
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *otxServer) setStatus(code int) {
	s.mu.Lock()
	s.status = code
	s.mu.Unlock()
}

func (s *otxServer) requests() []otxReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]otxReq(nil), s.reqs...)
}

func newOTXForTest(baseURL string, mods ...func(*otxBackend)) *otxBackend {
	b := &otxBackend{
		apiKey:     "otx-secret",
		baseURL:    baseURL,
		pulseName:  "test pulse",
		public:     true,
		tlp:        "white",
		tags:       []string{"honeypot"},
		batchSize:  2,
		flushEvery: time.Hour,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	for _, m := range mods {
		m(b)
	}
	return b
}

func (b *otxBackend) queued() []otxIndicator {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]otxIndicator(nil), b.batch...)
}

func (b *otxBackend) currentPulse() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pulseID
}

func otxRep(ip, proto string) Report { return Report{IP: ip, Protocol: proto} }

// ── Sanitize / Name ──────────────────────────────────────────────────────────

func TestOTX_NeverKeepsCredentials(t *testing.T) {
	b := newOTXForTest("")
	if u, p := b.Sanitize("root", "hunter2"); u != "" || p != "" {
		t.Errorf("got (%q,%q), OTX must not retain credentials", u, p)
	}
	if b.Name() != "OTX" {
		t.Errorf("Name() = %q", b.Name())
	}
}

// ── Report: conversion and batching ──────────────────────────────────────────

func TestOTX_ReportQueuesIndicators(t *testing.T) {
	b := newOTXForTest("", func(b *otxBackend) { b.batchSize = 10; b.role = "scanning_host" })
	b.Report(otxRep("198.51.100.7", "SSH"))
	b.Report(otxRep("2001:db8::1", "Telnet"))

	q := b.queued()
	if len(q) != 2 {
		t.Fatalf("queued %d, want 2", len(q))
	}
	if q[0].Indicator != "198.51.100.7" || q[0].Type != "IPv4" || q[0].Role != "scanning_host" {
		t.Errorf("ipv4 indicator = %+v", q[0])
	}
	if q[1].Indicator != "2001:db8::1" || q[1].Type != "IPv6" {
		t.Errorf("ipv6 indicator = %+v", q[1])
	}
	if !strings.Contains(q[0].Description, "SSH") || !strings.Contains(q[1].Description, "Telnet") {
		t.Errorf("descriptions should name the protocol: %q / %q", q[0].Description, q[1].Description)
	}
}

func TestOTX_ReportIgnoresInvalidIPAndDuplicates(t *testing.T) {
	logs := captureLogs(t)
	b := newOTXForTest("", func(b *otxBackend) { b.batchSize = 10 })

	b.Report(otxRep("not-an-ip", "SSH"))
	if len(b.queued()) != 0 {
		t.Fatal("invalid IP must not be queued")
	}
	logs.waitFor(t, "invalid IP")

	b.Report(otxRep("198.51.100.7", "SSH"))
	b.Report(otxRep("198.51.100.7", "Telnet"))
	if n := len(b.queued()); n != 1 {
		t.Errorf("duplicate IP queued, got %d entries", n)
	}
}

func TestOTX_ReportWaitsForFullBatch(t *testing.T) {
	srv := newOTXServer(t)
	b := newOTXForTest(srv.URL)

	b.Report(otxRep("198.51.100.1", "SSH"))
	if len(srv.requests()) != 0 {
		t.Fatal("submitted before the batch was full")
	}
	b.Report(otxRep("198.51.100.2", "SSH"))
	if len(srv.requests()) != 1 {
		t.Fatalf("got %d requests, want 1 once the batch is full", len(srv.requests()))
	}
	if len(b.queued()) != 0 {
		t.Error("queue should be empty after a successful submit")
	}
}

// ── wire format ──────────────────────────────────────────────────────────────

func TestOTX_FirstBatchCreatesPulseThenPatches(t *testing.T) {
	logs := captureLogs(t)
	srv := newOTXServer(t)
	b := newOTXForTest(srv.URL, func(b *otxBackend) { b.role = "scanning_host" })

	b.Report(otxRep("198.51.100.1", "SSH"))
	b.Report(otxRep("198.51.100.2", "SSH"))

	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("got %d requests", len(reqs))
	}
	r := reqs[0]
	if r.method != http.MethodPost || r.path != "/api/v1/pulses/create" {
		t.Errorf("first request = %s %s", r.method, r.path)
	}
	if r.header.Get("X-OTX-API-KEY") != "otx-secret" {
		t.Errorf("api key header = %q", r.header.Get("X-OTX-API-KEY"))
	}
	if r.header.Get("Content-Type") != "application/json" || r.header.Get("User-Agent") == "" {
		t.Errorf("headers = %v", r.header)
	}
	c := r.create(t)
	if c.Name != "test pulse" || !c.Public || c.TLP != "white" || len(c.Tags) != 1 || len(c.Indicators) != 2 {
		t.Errorf("create body = %+v", c)
	}
	if c.Indicators[0].Indicator != "198.51.100.1" || c.Indicators[0].Type != "IPv4" || c.Indicators[0].Role != "scanning_host" {
		t.Errorf("indicator = %+v", c.Indicators[0])
	}
	if b.currentPulse() != "pulse123" {
		t.Fatalf("pulse id = %q, want pulse123", b.currentPulse())
	}
	logs.waitFor(t, "OTX_PULSE_ID=pulse123")

	// Second batch must append to the same pulse, not create another one.
	b.Report(otxRep("198.51.100.3", "Telnet"))
	b.Report(otxRep("198.51.100.4", "Telnet"))

	reqs = srv.requests()
	if len(reqs) != 2 {
		t.Fatalf("got %d requests, want 2", len(reqs))
	}
	if reqs[1].method != http.MethodPatch || reqs[1].path != "/api/v1/pulses/pulse123" {
		t.Errorf("second request = %s %s", reqs[1].method, reqs[1].path)
	}
	add := reqs[1].edit(t).Indicators.Add
	if len(add) != 2 || add[0].Indicator != "198.51.100.3" {
		t.Errorf("patch indicators = %+v", add)
	}
	if strings.Contains(string(reqs[1].raw), `"name"`) {
		t.Error("patch body must contain only indicators")
	}
}

func TestOTX_ConfiguredPulseIDIsPatchedImmediately(t *testing.T) {
	srv := newOTXServer(t)
	b := newOTXForTest(srv.URL, func(b *otxBackend) { b.pulseID = "abc123" })

	b.Report(otxRep("198.51.100.1", "SSH"))
	b.Report(otxRep("198.51.100.2", "SSH"))

	reqs := srv.requests()
	if len(reqs) != 1 || reqs[0].method != http.MethodPatch || reqs[0].path != "/api/v1/pulses/abc123" {
		t.Fatalf("requests = %+v", reqs)
	}
}

func TestOTX_NoCredentialsOnTheWire(t *testing.T) {
	srv := newOTXServer(t)
	b := newOTXForTest(srv.URL)
	rep := Report{IP: "198.51.100.1", Protocol: "SSH", Creds: []Credential{{Time: time.Now(), Username: "root", Password: "hunter2"}}}
	b.Report(rep)
	rep.IP = "198.51.100.2"
	b.Report(rep)

	body := string(srv.requests()[0].raw)
	if strings.Contains(body, "root") || strings.Contains(body, "hunter2") || strings.Contains(body, "otx-secret") {
		t.Errorf("body leaks sensitive data: %s", body)
	}
}

func TestOTX_CreateWithoutIDInResponse(t *testing.T) {
	logs := captureLogs(t)
	srv := newOTXServer(t)
	srv.reply = `not json`
	b := newOTXForTest(srv.URL)

	b.Report(otxRep("198.51.100.1", "SSH"))
	b.Report(otxRep("198.51.100.2", "SSH"))

	if b.currentPulse() != "" {
		t.Error("no pulse id should be remembered")
	}
	if len(b.queued()) != 0 {
		t.Error("entries were accepted by the API and must not be requeued")
	}
	logs.waitFor(t, "no id")
}

func TestOTX_SubmitInvalidBaseURL(t *testing.T) {
	b := newOTXForTest("http://bad host")
	if retry, err := b.submit([]otxIndicator{{Indicator: "198.51.100.1", Type: "IPv4"}}); err == nil || retry {
		t.Errorf("got retry=%v err=%v, want permanent error", retry, err)
	}
}

// ── status handling / retries ────────────────────────────────────────────────

func TestOTX_FlushStatusHandling(t *testing.T) {
	cases := []struct {
		status      int
		wantRequeue bool
	}{
		{200, false}, {201, false},
		{400, false}, {401, false}, {403, false}, {404, false},
		{429, true}, {500, true}, {502, true}, {503, true},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			captureLogs(t)
			srv := newOTXServer(t)
			srv.setStatus(tc.status)
			b := newOTXForTest(srv.URL)
			b.batch = []otxIndicator{{Indicator: "198.51.100.1", Type: "IPv4"}}
			b.flush()

			if got := len(b.queued()) == 1; got != tc.wantRequeue {
				t.Errorf("requeued = %v, want %v", got, tc.wantRequeue)
			}
		})
	}
}

func TestOTX_FailedCreateDoesNotRememberPulse(t *testing.T) {
	captureLogs(t)
	srv := newOTXServer(t)
	srv.setStatus(500)
	b := newOTXForTest(srv.URL)
	b.batch = []otxIndicator{{Indicator: "198.51.100.1", Type: "IPv4"}}
	b.flush()
	if b.currentPulse() != "" {
		t.Error("pulse id stored for a failed create")
	}

	srv.setStatus(200)
	b.flush()
	reqs := srv.requests()
	if len(reqs) != 2 || reqs[1].method != http.MethodPost {
		t.Errorf("retry should create the pulse again: %+v", reqs)
	}
	if len(b.queued()) != 0 {
		t.Error("queue should be drained after the retry succeeded")
	}
}

func TestOTX_FlushEmptyQueueSendsNothing(t *testing.T) {
	srv := newOTXServer(t)
	b := newOTXForTest(srv.URL)
	b.flush()
	if len(srv.requests()) != 0 {
		t.Error("empty queue must not hit the API")
	}
}

func TestOTX_NetworkErrorRequeues(t *testing.T) {
	captureLogs(t)
	srv := newOTXServer(t)
	url := srv.URL
	srv.Close()
	b := newOTXForTest(url)
	b.batch = []otxIndicator{{Indicator: "198.51.100.1", Type: "IPv4"}}
	b.flush()
	if len(b.queued()) != 1 {
		t.Error("entries lost on network error")
	}
}

func TestOTX_RequeuedEntriesStayInFront(t *testing.T) {
	captureLogs(t)
	var b *otxBackend
	srv := newOTXServer(t)
	srv.setStatus(503)
	srv.onRequest = func() { // a new IP arrives while the failing request is in flight
		b.mu.Lock()
		b.batch = append(b.batch, otxIndicator{Indicator: "198.51.100.3"})
		b.mu.Unlock()
	}
	b = newOTXForTest(srv.URL, func(b *otxBackend) { b.batchSize = 1000 })
	b.batch = []otxIndicator{{Indicator: "198.51.100.1"}, {Indicator: "198.51.100.2"}}
	b.flush()

	got := b.queued()
	if len(got) != 3 || got[0].Indicator != "198.51.100.1" || got[1].Indicator != "198.51.100.2" || got[2].Indicator != "198.51.100.3" {
		t.Errorf("order = %+v, failed entries must stay in front", got)
	}
}

func TestOTX_QueueCapDropsOldest(t *testing.T) {
	captureLogs(t)
	srv := newOTXServer(t)
	srv.setStatus(503)
	b := newOTXForTest(srv.URL, func(b *otxBackend) { b.batchSize = 2 })
	for i := 0; i < 10; i++ {
		b.batch = append(b.batch, otxIndicator{Indicator: "10.0.0." + itoa(i)})
	}
	b.flush()

	q := b.queued()
	if len(q) != 2*otxMaxQueueFactor {
		t.Fatalf("queue length %d, want %d", len(q), 2*otxMaxQueueFactor)
	}
	if q[0].Indicator != "10.0.0.2" || q[len(q)-1].Indicator != "10.0.0.9" {
		t.Errorf("wrong entries dropped: first=%s last=%s", q[0].Indicator, q[len(q)-1].Indicator)
	}
}

func TestOTX_NeverFollowsRedirects(t *testing.T) {
	useEnv(t, "OTX_ENABLED", "true", "OTX_API_KEY", "k")
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

	be, _ := newOTXFromEnv()
	b := be.(*otxBackend)
	t.Cleanup(b.stop)
	b.baseURL = redirector.URL
	b.batch = []otxIndicator{{Indicator: "198.51.100.1", Type: "IPv4"}}
	b.flush()

	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatal("the redirect was followed: the API key would be sent to another host")
	}
	if len(b.queued()) != 0 {
		t.Error("a redirect response is a permanent failure and must not be retried forever")
	}
}

func TestOTX_ConcurrentFlushCreatesOnePulse(t *testing.T) {
	captureLogs(t)
	srv := newOTXServer(t)
	b := newOTXForTest(srv.URL, func(b *otxBackend) { b.batchSize = 1000 })

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b.Report(otxRep("198.51.100."+itoa(i+1), "SSH"))
			b.flush()
		}(i)
	}
	wg.Wait()

	creates, total := 0, 0
	for _, r := range srv.requests() {
		if r.method == http.MethodPost {
			creates++
			total += len(r.create(t).Indicators)
		} else {
			total += len(r.edit(t).Indicators.Add)
		}
	}
	if creates != 1 {
		t.Errorf("%d pulses created, want exactly 1", creates)
	}
	if total != 20 || len(b.queued()) != 0 {
		t.Errorf("sent %d indicators (queued %d), want 20 sent and none queued", total, len(b.queued()))
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestOTX_FlushLoopSendsPartialBatches(t *testing.T) {
	srv := newOTXServer(t)
	b := newOTXForTest(srv.URL, func(b *otxBackend) {
		b.batchSize = 100
		b.flushEvery = 10 * time.Millisecond
		b.done = make(chan struct{})
		b.loopDone = make(chan struct{})
	})
	go b.flushLoop()
	t.Cleanup(b.stop)

	b.Report(otxRep("198.51.100.1", "SSH"))

	deadline := time.Now().Add(2 * time.Second)
	for len(srv.requests()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(srv.requests()) != 1 {
		t.Fatal("flush loop did not send the partial batch")
	}
}

func TestOTX_StopEndsFlushLoopAndIsIdempotent(t *testing.T) {
	useEnv(t, "OTX_ENABLED", "true", "OTX_API_KEY", "k")
	be, _ := newOTXFromEnv()
	b := be.(*otxBackend)

	finished := make(chan struct{})
	go func() { b.stop(); b.stop(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() did not return: flushLoop is still running")
	}
}

// ── environment ──────────────────────────────────────────────────────────────

func TestNewOTXFromEnv_DisabledByDefault(t *testing.T) {
	useEnv(t)
	b, fields := newOTXFromEnv()
	if b != nil || fields != nil {
		t.Fatalf("expected (nil, nil), got (%v, %v)", b, fields)
	}
}

func TestNewOTXFromEnv_Defaults(t *testing.T) {
	useEnv(t, "OTX_ENABLED", "true", "OTX_API_KEY", "TOPSECRET")
	be, fields := newOTXFromEnv()
	b := be.(*otxBackend)
	t.Cleanup(b.stop)

	if b.apiKey != "TOPSECRET" || b.baseURL != otxDefaultBaseURL {
		t.Error("api key / base URL wrong")
	}
	if b.batchSize != 25 || b.flushEvery != time.Hour {
		t.Errorf("batch defaults = %d / %v", b.batchSize, b.flushEvery)
	}
	if !b.public || b.tlp != "white" || b.pulseID != "" || b.role != "bruteforce" || b.pulseName != otxDefaultPulseName {
		t.Errorf("defaults = %+v", b)
	}
	if strings.Join(b.tags, ",") != "honeypot,ssh,telnet,brute-force" {
		t.Errorf("tags = %v", b.tags)
	}
	if b.httpClient.Timeout == 0 || b.httpClient.CheckRedirect == nil {
		t.Error("http client must have a timeout and block redirects")
	}
	if fields["OTX_BATCH_SIZE"] != 25 || fields["OTX_BATCH_INTERVAL"] != "1h0m0s" || fields["OTX_TLP"] != "white" {
		t.Errorf("fields = %v", fields)
	}
	for k, v := range fields {
		if v == "TOPSECRET" {
			t.Errorf("field %s leaks the API key", k)
		}
	}
}

func TestNewOTXFromEnv_Overrides(t *testing.T) {
	useEnv(t, "OTX_ENABLED", "true", "OTX_API_KEY", "k",
		"OTX_PULSE_ID", "p1", "OTX_PULSE_NAME", "mine", "OTX_PUBLIC", "false", "OTX_TLP", "AMBER",
		"OTX_TAGS", " a, b ,,a", "OTX_INDICATOR_ROLE", "scanning_host",
		"OTX_BATCH_SIZE", "5", "OTX_BATCH_INTERVAL", "30s")
	be, fields := newOTXFromEnv()
	b := be.(*otxBackend)
	t.Cleanup(b.stop)

	if b.pulseID != "p1" || b.pulseName != "mine" || b.public || b.tlp != "amber" || b.role != "scanning_host" {
		t.Errorf("overrides not applied: %+v", b)
	}
	if strings.Join(b.tags, ",") != "a,b" {
		t.Errorf("tags = %v, want trimmed and de-duplicated", b.tags)
	}
	if b.batchSize != 5 || b.flushEvery != 30*time.Second || fields["OTX_PULSE_ID"] != "p1" {
		t.Errorf("batch/fields wrong: %d %v %v", b.batchSize, b.flushEvery, fields)
	}
}

func TestNewOTXFromEnv_InvalidConfigIsFatal(t *testing.T) {
	base := []string{"OTX_ENABLED", "true", "OTX_API_KEY", "k"}
	cases := []struct {
		name string
		kv   []string
		want string
	}{
		{"missing key", []string{"OTX_ENABLED", "true"}, "OTX_API_KEY"},
		{"batch size text", []string{"OTX_BATCH_SIZE", "abc"}, "OTX_BATCH_SIZE"},
		{"batch size zero", []string{"OTX_BATCH_SIZE", "0"}, "OTX_BATCH_SIZE"},
		{"batch size negative", []string{"OTX_BATCH_SIZE", "-1"}, "OTX_BATCH_SIZE"},
		{"interval text", []string{"OTX_BATCH_INTERVAL", "often"}, "OTX_BATCH_INTERVAL"},
		{"interval zero", []string{"OTX_BATCH_INTERVAL", "0s"}, "OTX_BATCH_INTERVAL"},
		{"unknown tlp", []string{"OTX_TLP", "purple"}, "OTX_TLP"},
		{"public amber", []string{"OTX_TLP", "amber"}, "OTX_TLP"},
		{"public red", []string{"OTX_TLP", "red"}, "OTX_TLP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kv := append([]string{}, base...)
			if tc.name == "missing key" {
				kv = tc.kv
			} else {
				kv = append(kv, tc.kv...)
			}
			useEnv(t, kv...)
			msg := expectFatal(t, func() { newOTXFromEnv() })
			if !strings.Contains(msg, tc.want) {
				t.Errorf("message %q does not name %s", msg, tc.want)
			}
		})
	}
}

func TestOTX_RegisteredAndSharedCoreFlow(t *testing.T) {
	useEnv(t, "OTX_ENABLED", "true", "OTX_API_KEY", "k", "OTX_BATCH_SIZE", "1")
	logs := captureLogs(t)

	found := false
	for _, f := range abuseBackendFactories {
		if b, _ := f(); b != nil {
			if ob, ok := b.(*otxBackend); ok {
				found = true
				ob.stop()
			}
		}
	}
	if !found {
		t.Fatal("newOTXFromEnv is not registered in abuseBackendFactories")
	}

	srv := newOTXServer(t)
	ob := newOTXForTest(srv.URL, func(b *otxBackend) { b.batchSize = 1 })
	m := NewManager([]Backend{ob}, 2, time.Minute, time.Hour, time.Hour)
	t.Cleanup(m.Stop)

	m.RecordFailure("198.51.100.9", "SSH", "root", "pw")
	if !m.RecordFailure("198.51.100.9", "SSH", "root", "pw2") {
		t.Fatal("threshold not reached")
	}

	deadline := time.Now().Add(2 * time.Second)
	for len(srv.requests()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("got %d requests", len(reqs))
	}
	// The report goroutine logs after the response; wait so it cannot outlive the test's logger restore.
	logs.waitFor(t, "OTX: indicators submitted")
	c := reqs[0].create(t)
	if len(c.Indicators) != 1 || c.Indicators[0].Indicator != "198.51.100.9" {
		t.Errorf("indicators = %+v", c.Indicators)
	}
	if strings.Contains(string(reqs[0].raw), "root") {
		t.Error("username leaked")
	}
}