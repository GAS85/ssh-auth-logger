package abuse

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// ── fake reputation backend ──────────────────────────────────────────────────

// fakeChecker is a Backend that can also look up IP reputation.
type fakeChecker struct {
	*fakeBackend
	enabled bool

	mu    sync.Mutex
	calls []string
	rep   Reputation
	err   error
	gate  chan struct{} // if set, lookups block until it is closed
}

func newFakeChecker(rep Reputation) *fakeChecker {
	return &fakeChecker{fakeBackend: newFake("Checker"), enabled: true, rep: rep}
}

func (f *fakeChecker) ReputationCheckEnabled() bool { return f.enabled }

func (f *fakeChecker) LookupReputation(ip string) (Reputation, error) {
	f.mu.Lock()
	f.calls = append(f.calls, ip)
	gate, rep, err := f.gate, f.rep, f.err
	f.mu.Unlock()

	if gate != nil {
		<-gate
	}
	return rep, err
}

func (f *fakeChecker) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeChecker) set(rep Reputation, err error) {
	f.mu.Lock()
	f.rep, f.err = rep, err
	f.mu.Unlock()
}

// waitCalls waits until the checker has been called n times.
func (f *fakeChecker) waitCalls(t *testing.T, n int) {
	t.Helper()
	waitFor(t, func() bool { return f.callCount() >= n }, "lookup call")
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// waitSettled waits until no lookup is in flight for ip.
func waitSettled(t *testing.T, m *Manager, ip string) {
	t.Helper()
	waitFor(t, func() bool {
		m.repMu.Lock()
		defer m.repMu.Unlock()
		e, ok := m.rep[ip]
		return ok && !e.pending
	}, "lookup to finish")
}

// expire makes the cache entry of ip look old.
func expire(m *Manager, ip string) {
	m.repMu.Lock()
	defer m.repMu.Unlock()
	m.rep[ip].expires = time.Now().Add(-time.Second)
}

func newRepManager(t *testing.T, expiry time.Duration, backends ...Backend) *Manager {
	t.Helper()
	return stoppable(t, NewManager(backends, 10, time.Hour, time.Hour, expiry))
}

var sampleRep = Reputation{CountryCode: "SC", AbuseConfidenceScore: 100, TotalReports: 73}

// ── Manager: reputation cache ────────────────────────────────────────────────

func TestReputation_FirstSightIsNotBlockedBySlowAPI(t *testing.T) {
	f := newFakeChecker(sampleRep)
	f.gate = make(chan struct{})
	m := newRepManager(t, time.Hour, f)

	start := time.Now()
	got := m.ReputationFields("192.0.2.1")
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("ReputationFields blocked for %v while the API was slow", elapsed)
	}
	if got != nil {
		t.Fatalf("first sight must have no reputation yet, got %v", got)
	}

	// Still nothing while the lookup is in flight, and no second lookup is started.
	f.waitCalls(t, 1)
	if got := m.ReputationFields("192.0.2.1"); got != nil {
		t.Errorf("pending lookup returned %v", got)
	}

	close(f.gate)
	waitSettled(t, m, "192.0.2.1")

	got = m.ReputationFields("192.0.2.1")
	if got["countryCode"] != "SC" || got["abuseConfidenceScore"] != 100 || got["totalReports"] != 73 {
		t.Fatalf("fields after lookup = %v", got)
	}
	if n := f.callCount(); n != 1 {
		t.Errorf("lookups = %d, want 1", n)
	}
}

func TestReputation_CachedDataIsReturnedForEveryNextConnection(t *testing.T) {
	f := newFakeChecker(sampleRep)
	m := newRepManager(t, time.Hour, f)

	m.ReputationFields("192.0.2.2")
	waitSettled(t, m, "192.0.2.2")

	for i := 0; i < 10; i++ {
		got := m.ReputationFields("192.0.2.2")
		if got["countryCode"] != "SC" || got["abuseConfidenceScore"] != 100 || got["totalReports"] != 73 {
			t.Fatalf("connection %d: fields = %v", i, got)
		}
	}
	if n := f.callCount(); n != 1 {
		t.Errorf("API called %d times for one IP, want 1", n)
	}
}

func TestReputation_IPsAreCachedIndependently(t *testing.T) {
	f := newFakeChecker(sampleRep)
	m := newRepManager(t, time.Hour, f)

	m.ReputationFields("192.0.2.3")
	waitSettled(t, m, "192.0.2.3")

	if got := m.ReputationFields("192.0.2.4"); got != nil {
		t.Errorf("a different IP must not see cached data, got %v", got)
	}
	f.waitCalls(t, 2)
}

func TestReputation_ConcurrentConnectionsStartOneLookup(t *testing.T) {
	f := newFakeChecker(sampleRep)
	f.gate = make(chan struct{})
	m := newRepManager(t, time.Hour, f)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.ReputationFields("192.0.2.5")
		}()
	}
	wg.Wait()
	f.waitCalls(t, 1)
	time.Sleep(20 * time.Millisecond)
	close(f.gate)

	if n := f.callCount(); n != 1 {
		t.Errorf("lookups = %d, want exactly 1", n)
	}
}

func TestReputation_CacheLivesForStateExpiry(t *testing.T) {
	f := newFakeChecker(sampleRep)
	m := newRepManager(t, 90*time.Minute, f)

	m.ReputationFields("192.0.2.6")
	waitSettled(t, m, "192.0.2.6")

	m.repMu.Lock()
	ttl := time.Until(m.rep["192.0.2.6"].expires)
	m.repMu.Unlock()
	if ttl < 89*time.Minute || ttl > 90*time.Minute {
		t.Errorf("cache TTL = %v, want ABUSE_STATE_EXPIRY (90m)", ttl)
	}
}

func TestReputation_ExpiredEntryIsRefreshed(t *testing.T) {
	f := newFakeChecker(sampleRep)
	m := newRepManager(t, time.Hour, f)

	m.ReputationFields("192.0.2.7")
	waitSettled(t, m, "192.0.2.7")
	expire(m, "192.0.2.7")

	f.set(Reputation{CountryCode: "DE", AbuseConfidenceScore: 5, TotalReports: 1}, nil)

	// Expired data is not shown; a refresh starts instead.
	if got := m.ReputationFields("192.0.2.7"); got != nil {
		t.Fatalf("expired data was still returned: %v", got)
	}
	f.waitCalls(t, 2)
	waitSettled(t, m, "192.0.2.7")

	got := m.ReputationFields("192.0.2.7")
	if got["countryCode"] != "DE" || got["abuseConfidenceScore"] != 5 || got["totalReports"] != 1 {
		t.Errorf("refreshed fields = %v", got)
	}
}

func TestReputation_FailedLookupIsNotRetriedImmediately(t *testing.T) {
	f := newFakeChecker(Reputation{})
	f.err = errors.New("boom")
	m := newRepManager(t, time.Hour, f)

	if got := m.ReputationFields("192.0.2.8"); got != nil {
		t.Fatalf("got %v", got)
	}
	waitSettled(t, m, "192.0.2.8")

	for i := 0; i < 5; i++ {
		if got := m.ReputationFields("192.0.2.8"); got != nil {
			t.Fatalf("failed lookup returned data: %v", got)
		}
	}
	if n := f.callCount(); n != 1 {
		t.Fatalf("lookups = %d, want 1 (failure must be cached)", n)
	}

	m.repMu.Lock()
	retry := time.Until(m.rep["192.0.2.8"].expires)
	m.repMu.Unlock()
	if retry <= 0 || retry > reputationRetryAfter {
		t.Errorf("retry delay = %v, want within (0, %v]", retry, reputationRetryAfter)
	}

	// Once the failure entry is old, the API is tried again and can recover.
	expire(m, "192.0.2.8")
	f.set(sampleRep, nil)
	m.ReputationFields("192.0.2.8")
	f.waitCalls(t, 2)
	waitSettled(t, m, "192.0.2.8")
	if got := m.ReputationFields("192.0.2.8"); got["totalReports"] != 73 {
		t.Errorf("after recovery fields = %v", got)
	}
}

func TestReputation_FailureRetryNeverExceedsStateExpiry(t *testing.T) {
	f := newFakeChecker(Reputation{})
	f.err = errors.New("boom")
	m := newRepManager(t, time.Minute, f)

	m.ReputationFields("192.0.2.9")
	waitSettled(t, m, "192.0.2.9")

	m.repMu.Lock()
	retry := time.Until(m.rep["192.0.2.9"].expires)
	m.repMu.Unlock()
	if retry > time.Minute {
		t.Errorf("retry delay %v exceeds state expiry", retry)
	}
}

func TestReputation_EmptyCountryIsShownAsNA(t *testing.T) {
	f := newFakeChecker(Reputation{AbuseConfidenceScore: 0, TotalReports: 0})
	m := newRepManager(t, time.Hour, f)

	m.ReputationFields("192.0.2.10")
	waitSettled(t, m, "192.0.2.10")

	got := m.ReputationFields("192.0.2.10")
	if got["countryCode"] != "N/A" || got["abuseConfidenceScore"] != 0 || got["totalReports"] != 0 {
		t.Errorf("fields = %v", got)
	}
}

func TestReputation_Disabled(t *testing.T) {
	t.Run("checker switched off", func(t *testing.T) {
		f := newFakeChecker(sampleRep)
		f.enabled = false
		m := newRepManager(t, time.Hour, f)

		if got := m.ReputationFields("192.0.2.11"); got != nil {
			t.Errorf("got %v", got)
		}
		time.Sleep(20 * time.Millisecond)
		if f.callCount() != 0 {
			t.Error("lookup made although the check is disabled")
		}
	})

	t.Run("backend without reputation support", func(t *testing.T) {
		m := newRepManager(t, time.Hour, newFake("plain"))
		if got := m.ReputationFields("192.0.2.12"); got != nil {
			t.Errorf("got %v", got)
		}
	})

	t.Run("no backends", func(t *testing.T) {
		m := NewManager(nil, 1, time.Hour, time.Hour, time.Hour)
		if got := m.ReputationFields("192.0.2.13"); got != nil {
			t.Errorf("got %v", got)
		}
	})

	t.Run("nil manager", func(t *testing.T) {
		var m *Manager
		if got := m.ReputationFields("192.0.2.14"); got != nil {
			t.Errorf("got %v", got)
		}
	})
}

func TestReputation_InvalidIPIsIgnored(t *testing.T) {
	f := newFakeChecker(sampleRep)
	m := newRepManager(t, time.Hour, f)

	for _, bad := range []string{"", "not-an-ip", "1.2.3", "1.2.3.4:22", "999.1.1.1"} {
		if got := m.ReputationFields(bad); got != nil {
			t.Errorf("%q returned %v", bad, got)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if f.callCount() != 0 {
		t.Error("lookup made for an invalid IP")
	}
}

func TestReputation_IPv6(t *testing.T) {
	f := newFakeChecker(sampleRep)
	m := newRepManager(t, time.Hour, f)

	m.ReputationFields("2001:db8::1")
	waitSettled(t, m, "2001:db8::1")
	if got := m.ReputationFields("2001:db8::1"); got["countryCode"] != "SC" {
		t.Errorf("fields = %v", got)
	}
}

func TestReputation_FirstEnabledCheckerIsUsed(t *testing.T) {
	off := newFakeChecker(Reputation{CountryCode: "XX"})
	off.enabled = false
	on := newFakeChecker(sampleRep)
	m := newRepManager(t, time.Hour, newFake("plain"), off, on)

	m.ReputationFields("192.0.2.15")
	waitSettled(t, m, "192.0.2.15")

	if off.callCount() != 0 || on.callCount() != 1 {
		t.Errorf("calls: disabled=%d enabled=%d", off.callCount(), on.callCount())
	}
}

func TestReputation_CleanupRemovesOnlyExpiredEntries(t *testing.T) {
	m := newRepManager(t, time.Hour, newFakeChecker(sampleRep))
	now := time.Now()

	m.repMu.Lock()
	m.rep["192.0.2.20"] = &reputationEntry{ok: true, expires: now.Add(-time.Minute)} // expired
	m.rep["192.0.2.21"] = &reputationEntry{expires: now.Add(-time.Minute)}           // expired failure
	m.rep["192.0.2.22"] = &reputationEntry{ok: true, expires: now.Add(time.Hour)}    // fresh
	m.rep["192.0.2.23"] = &reputationEntry{pending: true}                            // in flight
	m.repMu.Unlock()

	m.cleanupReputation(now)

	m.repMu.Lock()
	defer m.repMu.Unlock()
	for _, ip := range []string{"192.0.2.20", "192.0.2.21"} {
		if _, ok := m.rep[ip]; ok {
			t.Errorf("%s should have been purged", ip)
		}
	}
	for _, ip := range []string{"192.0.2.22", "192.0.2.23"} {
		if _, ok := m.rep[ip]; !ok {
			t.Errorf("%s must be kept", ip)
		}
	}
}

func TestReputation_CleanupLoopPurgesExpiredEntries(t *testing.T) {
	m := stoppable(t, NewManager([]Backend{newFakeChecker(sampleRep)}, 3, time.Hour, 10*time.Millisecond, time.Hour))

	m.repMu.Lock()
	m.rep["192.0.2.24"] = &reputationEntry{ok: true, expires: time.Now().Add(-time.Second)}
	m.repMu.Unlock()

	waitFor(t, func() bool {
		m.repMu.Lock()
		defer m.repMu.Unlock()
		return len(m.rep) == 0
	}, "cleanup loop to purge reputation entries")
}

// ── AbuseIPDB: CHECK endpoint ────────────────────────────────────────────────

// The example answer from https://docs.abuseipdb.com/#check-endpoint
const abuseIPDBCheckJSON = `{
  "data": {
    "ipAddress": "64.89.160.146",
    "isPublic": true,
    "ipVersion": 4,
    "isWhitelisted": false,
    "abuseConfidenceScore": 100,
    "countryCode": "SC",
    "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Blatant Technologies, LLC",
    "domain": "blatant.host",
    "hostnames": [],
    "isTor": false,
    "totalReports": 73,
    "numDistinctUsers": 27,
    "lastReportedAt": "2026-10-08T04:05:39+00:00"
  }
}`

func resp(status int, body string, hdr ...string) *http.Response {
	h := http.Header{}
	for i := 0; i+1 < len(hdr); i += 2 {
		h.Set(hdr[i], hdr[i+1])
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     h,
	}
}

func TestAbuseIPDB_LookupReputation_RequestAndParsing(t *testing.T) {
	var got *http.Request
	b := newAbuseIPDBForTest(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		got = r
		return resp(200, abuseIPDBCheckJSON), nil
	}))

	rep, err := b.LookupReputation("64.89.160.146")
	if err != nil {
		t.Fatal(err)
	}
	if rep != (Reputation{CountryCode: "SC", AbuseConfidenceScore: 100, TotalReports: 73}) {
		t.Errorf("reputation = %+v", rep)
	}

	if got.Method != http.MethodGet || got.URL.Scheme != "https" ||
		got.URL.Host != "api.abuseipdb.com" || got.URL.Path != "/api/v2/check" {
		t.Errorf("request = %s %s", got.Method, got.URL)
	}
	q := got.URL.Query()
	if q.Get("ipAddress") != "64.89.160.146" || q.Get("maxAgeInDays") != "30" {
		t.Errorf("query = %v", q)
	}
	if got.Header.Get("Key") != "test-api-key" || got.Header.Get("Accept") != "application/json" {
		t.Errorf("headers = %v", got.Header)
	}
}

func TestAbuseIPDB_LookupReputation_IPv6IsEscaped(t *testing.T) {
	var got *http.Request
	b := newAbuseIPDBForTest(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		got = r
		return resp(200, abuseIPDBCheckJSON), nil
	}))
	if _, err := b.LookupReputation("2001:db8::1"); err != nil {
		t.Fatal(err)
	}
	if v := got.URL.Query().Get("ipAddress"); v != "2001:db8::1" {
		t.Errorf("ipAddress = %q", v)
	}
}

func TestAbuseIPDB_LookupReputation_NullCountry(t *testing.T) {
	b := newAbuseIPDBForTest(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return resp(200, `{"data":{"countryCode":null,"abuseConfidenceScore":0,"totalReports":0}}`), nil
	}))
	rep, err := b.LookupReputation("10.0.0.1")
	if err != nil || rep.CountryCode != "" {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
}

func TestAbuseIPDB_LookupReputation_Errors(t *testing.T) {
	t.Run("rejected status is logged and returned", func(t *testing.T) {
		hook := captureLogs(t)
		b := newAbuseIPDBForTest(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return resp(401, `{"errors":[{"detail":"bad key"}]}`), nil
		}))
		if _, err := b.LookupReputation("192.0.2.30"); err == nil {
			t.Fatal("expected an error")
		}
		e := hook.find("reputation check rejected")
		if e == nil || e.Data["ip"] != "192.0.2.30" || e.Data["body"] != `{"errors":[{"detail":"bad key"}]}` {
			t.Fatalf("log entry = %+v", e)
		}
		if b.isPaused() {
			t.Error("a 401 must not pause lookups")
		}
	})

	t.Run("body is bounded", func(t *testing.T) {
		hook := captureLogs(t)
		b := newAbuseIPDBForTest(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return resp(500, strings.Repeat("x", 100_000)), nil
		}))
		b.LookupReputation("192.0.2.31")
		e := hook.find("reputation check rejected")
		if e == nil || len(e.Data["body"].(string)) != 4096 {
			t.Fatalf("log entry = %+v", e)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		hook := captureLogs(t)
		b := newAbuseIPDBForTest(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}))
		if _, err := b.LookupReputation("192.0.2.32"); err == nil {
			t.Fatal("expected an error")
		}
		if hook.find("check request failed") == nil {
			t.Error("transport error not logged")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		hook := captureLogs(t)
		b := newAbuseIPDBForTest(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return resp(200, `<html>oops</html>`), nil
		}))
		if _, err := b.LookupReputation("192.0.2.33"); err == nil {
			t.Fatal("expected an error")
		}
		if hook.find("invalid check response") == nil {
			t.Error("decode error not logged")
		}
	})
}

func TestAbuseIPDB_LookupReputation_RateLimitPausesLookups(t *testing.T) {
	var calls atomic.Int32
	b := newAbuseIPDBForTest(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return resp(429, `{"errors":[{"detail":"Daily rate limit exceeded."}]}`, "Retry-After", "120"), nil
	}))

	if _, err := b.LookupReputation("192.0.2.34"); err == nil {
		t.Fatal("expected an error")
	}

	// While paused, no request leaves the process.
	for i := 0; i < 5; i++ {
		if _, err := b.LookupReputation("192.0.2.35"); !errors.Is(err, errAbuseIPDBPaused) {
			t.Fatalf("err = %v, want errAbuseIPDBPaused", err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("HTTP requests = %d, want 1", n)
	}

	b.pauseMu.Lock()
	remaining := time.Until(b.pausedUntil)
	b.pauseMu.Unlock()
	if remaining < 110*time.Second || remaining > 120*time.Second {
		t.Errorf("pause = %v, want about the Retry-After of 120s", remaining)
	}

	// After the pause, lookups resume.
	b.pauseMu.Lock()
	b.pausedUntil = time.Now().Add(-time.Second)
	b.pauseMu.Unlock()
	b.LookupReputation("192.0.2.36")
	if n := calls.Load(); n != 2 {
		t.Errorf("HTTP requests after pause = %d, want 2", n)
	}
}

func TestAbuseIPDB_PauseFor(t *testing.T) {
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"60", 60 * time.Second},
		{" 90 ", 90 * time.Second},
		{"", abuseIPDBDefaultPause},
		{"garbage", abuseIPDBDefaultPause},
		{"0", abuseIPDBDefaultPause},
		{"-5", abuseIPDBDefaultPause},
		{"999999999", abuseIPDBMaxPause},
	}
	for _, tc := range cases {
		b := newAbuseIPDBForTest(nil)
		if got := b.pauseFor(tc.header); got != tc.want {
			t.Errorf("pauseFor(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}

// ── AbuseIPDB: configuration ─────────────────────────────────────────────────

func TestNewAbuseIPDBFromEnv_IPCheck(t *testing.T) {
	t.Run("off by default", func(t *testing.T) {
		useEnv(t, "ABUSEIPDB_ENABLED", "true", "ABUSEIPDB_API_KEY", "k")
		be, fields := newAbuseIPDBFromEnv()
		b := be.(*abuseIPDBBackend)
		if b.ReputationCheckEnabled() {
			t.Error("IP check must be off by default")
		}
		if fields["abuseipdb"].(logrus.Fields)["ABUSEIPDB_IP_CHECK"] != false {
			t.Errorf("startup fields = %v", fields)
		}
	})

	t.Run("enabled", func(t *testing.T) {
		useEnv(t, "ABUSEIPDB_ENABLED", "true", "ABUSEIPDB_API_KEY", "k", "ABUSEIPDB_IP_CHECK", "true")
		be, fields := newAbuseIPDBFromEnv()
		b := be.(*abuseIPDBBackend)
		if !b.ReputationCheckEnabled() {
			t.Error("IP check not enabled")
		}
		if fields["abuseipdb"].(logrus.Fields)["ABUSEIPDB_IP_CHECK"] != true {
			t.Errorf("startup fields = %v", fields)
		}
	})

	t.Run("needs the backend itself to be enabled", func(t *testing.T) {
		useEnv(t, "ABUSEIPDB_IP_CHECK", "true")
		if b, _ := newAbuseIPDBFromEnv(); b != nil {
			t.Error("ABUSEIPDB_IP_CHECK alone must not enable the backend")
		}
	})
}

// ── End to end: Manager + AbuseIPDB backend ──────────────────────────────────

func TestReputation_EndToEndWithAbuseIPDB(t *testing.T) {
	var calls atomic.Int32
	b := newAbuseIPDBForTest(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return resp(200, abuseIPDBCheckJSON), nil
	}), func(b *abuseIPDBBackend) { b.checkIP = true })
	m := newRepManager(t, time.Hour, b)

	// First connection: logged without reputation, lookup runs in the background.
	if got := m.ReputationFields("64.89.160.146"); got != nil {
		t.Fatalf("first connection got %v", got)
	}
	waitSettled(t, m, "64.89.160.146")

	// Every later connection carries the cached data, without another API call.
	for i := 0; i < 3; i++ {
		got := m.ReputationFields("64.89.160.146")
		if got["countryCode"] != "SC" || got["abuseConfidenceScore"] != 100 || got["totalReports"] != 73 {
			t.Fatalf("connection %d: %v", i+2, got)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("API calls = %d, want 1", n)
	}
}

func TestReputation_AbuseIPDBWithCheckOffMakesNoRequests(t *testing.T) {
	var calls atomic.Int32
	b := newAbuseIPDBForTest(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return resp(200, abuseIPDBCheckJSON), nil
	}))
	m := newRepManager(t, time.Hour, b)

	m.ReputationFields("192.0.2.40")
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 0 {
		t.Error("request made although ABUSEIPDB_IP_CHECK is off")
	}
}