package abuse

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// fakeBackend records the reports it receives.
type fakeBackend struct {
	name     string
	sanitize func(u, p string) (string, string)
	reports  chan Report
}

func asFields(v any) (map[string]any, bool) {
	switch x := v.(type) {
	case map[string]any:
		return x, true
	case logrus.Fields:
		return map[string]any(x), true
	default:
		return nil, false
	}
}

func newFake(name string) *fakeBackend {
	return &fakeBackend{name: name, reports: make(chan Report, 64)}
}

func (f *fakeBackend) Name() string { return f.name }

func (f *fakeBackend) Sanitize(u, p string) (string, string) {
	if f.sanitize != nil {
		return f.sanitize(u, p)
	}
	return u, p
}

func (f *fakeBackend) Report(r Report) { f.reports <- r }

func (f *fakeBackend) next(t *testing.T) Report {
	t.Helper()
	select {
	case r := <-f.reports:
		return r
	case <-time.After(2 * time.Second):
		t.Fatalf("backend %s: timed out waiting for a report", f.name)
		return Report{}
	}
}

func (f *fakeBackend) expectNone(t *testing.T) {
	t.Helper()
	select {
	case r := <-f.reports:
		t.Fatalf("backend %s: unexpected report %+v", f.name, r)
	case <-time.After(30 * time.Millisecond):
	}
}

func newTestManager(limit int, backends ...Backend) *Manager {
	return NewManager(backends, limit, time.Hour, time.Hour, time.Hour)
}

// stoppable registers m.Stop for the end of the test.
func stoppable(t *testing.T, m *Manager) *Manager {
	t.Helper()
	t.Cleanup(m.Stop)
	return m
}

// snapshot reads the state of one IP under the manager lock.
func snapshot(m *Manager, ip string) (attempts int, lastReported time.Time, creds [][]Credential, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.ips[ip]
	if !ok {
		return 0, time.Time{}, nil, false
	}
	return s.attempts, s.lastReported, s.creds, true
}

// ── RecordFailure ────────────────────────────────────────────────────────────

func TestRecordFailure_NilManagerIsNoop(t *testing.T) {
	var m *Manager
	if m.RecordFailure("192.0.2.1", "SSH", "root", "pw") {
		t.Fatal("nil manager must not report")
	}
}

func TestRecordFailure_NoBackendsIsNoop(t *testing.T) {
	m := NewManager(nil, 1, time.Hour, time.Hour, time.Hour)
	if m.RecordFailure("192.0.2.1", "SSH", "root", "pw") {
		t.Fatal("manager without backends must not report")
	}
	if len(m.ips) != 0 {
		t.Fatalf("manager without backends created state: %v", m.ips)
	}
}

func TestRecordFailure_InvalidIP(t *testing.T) {
	hook := captureLogs(t)
	f := newFake("A")
	m := newTestManager(1, f)

	for _, bad := range []string{"not-an-ip", "", "1.2.3", "1.2.3.4:22", "999.1.1.1"} {
		if m.RecordFailure(bad, "SSH", "root", "pw") {
			t.Errorf("invalid IP %q reported", bad)
		}
	}
	if len(m.ips) != 0 {
		t.Fatalf("invalid IPs created state: %v", m.ips)
	}
	if hook.find("invalid IP address") == nil {
		t.Error("expected a warning for invalid IP")
	}
	f.expectNone(t)
}

func TestRecordFailure_AcceptsIPv4AndIPv6(t *testing.T) {
	f := newFake("A")
	m := newTestManager(1, f)
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		if !m.RecordFailure(ip, "SSH", "u", "p") {
			t.Errorf("valid IP %q was not reported at threshold 1", ip)
		}
		if r := f.next(t); r.IP != ip {
			t.Errorf("report IP = %q, want %q", r.IP, ip)
		}
	}
}

func TestRecordFailure_ThresholdReportsOnceWithCredentials(t *testing.T) {
	hook := captureLogs(t)
	f := newFake("A")
	m := newTestManager(3, f)
	ip := "192.0.2.10"

	if m.RecordFailure(ip, "SSH", "root", "pw1") || m.RecordFailure(ip, "SSH", "root", "pw2") {
		t.Fatal("reported before reaching the threshold")
	}
	f.expectNone(t)

	if !m.RecordFailure(ip, "SSH", "admin", "pw3") {
		t.Fatal("threshold reached but no report scheduled")
	}

	r := f.next(t)
	if r.IP != ip || r.Protocol != "SSH" {
		t.Errorf("report = %+v, want IP %s protocol SSH", r, ip)
	}
	if len(r.Creds) != 3 {
		t.Fatalf("got %d creds, want 3: %+v", len(r.Creds), r.Creds)
	}
	if r.Creds[0].Username != "root" || r.Creds[0].Password != "pw1" || r.Creds[2].Username != "admin" {
		t.Errorf("unexpected creds: %+v", r.Creds)
	}
	for _, c := range r.Creds {
		if c.Time.IsZero() {
			t.Error("credential without timestamp")
		}
	}

	attempts, lastReported, creds, ok := snapshot(m, ip)
	if !ok || attempts != 0 || lastReported.IsZero() || len(creds[0]) != 0 {
		t.Errorf("state after report: attempts=%d lastReported=%v creds=%v", attempts, lastReported, creds)
	}

	if hook.find("report threshold reached") == nil {
		t.Error("expected threshold log message")
	}
}

func TestRecordFailure_ThresholdOfOne(t *testing.T) {
	f := newFake("A")
	m := newTestManager(1, f)
	if !m.RecordFailure("192.0.2.11", "Telnet", "u", "p") {
		t.Fatal("threshold 1 must report on first failure")
	}
	if r := f.next(t); r.Protocol != "Telnet" {
		t.Errorf("protocol = %q, want Telnet", r.Protocol)
	}
}

func TestRecordFailure_CooldownCollectsCredentialsButDoesNotCount(t *testing.T) {
	f := newFake("A")
	m := newTestManager(2, f)
	ip := "192.0.2.20"

	m.RecordFailure(ip, "SSH", "root", "one")
	if !m.RecordFailure(ip, "SSH", "root", "two") {
		t.Fatal("expected first report")
	}
	f.next(t)

	for i := 0; i < 5; i++ {
		if m.RecordFailure(ip, "SSH", fmt.Sprintf("cool%d", i), "p") {
			t.Fatal("report scheduled during cooldown")
		}
	}
	f.expectNone(t)

	attempts, _, creds, _ := snapshot(m, ip)
	if attempts != 0 {
		t.Errorf("attempts during cooldown = %d, want 0", attempts)
	}
	if len(creds[0]) != 5 {
		t.Errorf("credentials collected during cooldown = %d, want 5", len(creds[0]))
	}

	// Expire the cooldown deterministically.
	m.mu.Lock()
	m.ips[ip].lastReported = time.Now().Add(-2 * time.Hour)
	m.mu.Unlock()

	if m.RecordFailure(ip, "SSH", "after1", "p") {
		t.Fatal("first failure after cooldown must only count (limit 2)")
	}
	if !m.RecordFailure(ip, "SSH", "after2", "p") {
		t.Fatal("second failure after cooldown should report")
	}

	r := f.next(t)
	if len(r.Creds) != 7 {
		t.Errorf("second report has %d creds, want 5 (cooldown) + 2 = 7", len(r.Creds))
	}
}

func TestRecordFailure_IPsAreTrackedIndependently(t *testing.T) {
	f := newFake("A")
	m := newTestManager(2, f)

	m.RecordFailure("192.0.2.31", "SSH", "a", "p")
	m.RecordFailure("192.0.2.32", "SSH", "b", "p")
	f.expectNone(t) // 1 failure each, threshold 2

	if !m.RecordFailure("192.0.2.31", "SSH", "a2", "p") {
		t.Fatal("second IP .31 failure should report")
	}
	r := f.next(t)
	if r.IP != "192.0.2.31" {
		t.Errorf("reported IP %q, want 192.0.2.31", r.IP)
	}
	for _, c := range r.Creds {
		if c.Username == "b" {
			t.Error("credentials from another IP leaked into the report")
		}
	}
}

func TestRecordFailure_DuplicateCredentialsStoredOnce(t *testing.T) {
	f := newFake("A")
	m := newTestManager(4, f)
	ip := "192.0.2.33"
	for i := 0; i < 4; i++ {
		m.RecordFailure(ip, "SSH", "root", "same")
	}
	r := f.next(t)
	if len(r.Creds) != 1 {
		t.Errorf("identical attempts should be de-duplicated, got %d creds", len(r.Creds))
	}
}

func TestRecordFailure_PerBackendSanitizeAndDispatch(t *testing.T) {
	hook := captureLogs(t)

	a := newFake("A") // keeps everything
	b := newFake("B") // never sees passwords
	b.sanitize = func(u, _ string) (string, string) { return u, "" }
	c := newFake("C") // sees nothing
	c.sanitize = func(string, string) (string, string) { return "", "" }

	m := newTestManager(2, a, b, c)
	ip := "192.0.2.40"
	m.RecordFailure(ip, "SSH", "root", "secret1")
	if !m.RecordFailure(ip, "Telnet", "admin", "secret2") {
		t.Fatal("expected report")
	}

	ra, rb, rc := a.next(t), b.next(t), c.next(t)

	for name, r := range map[string]Report{"A": ra, "B": rb, "C": rc} {
		if r.IP != ip {
			t.Errorf("%s: IP = %q", name, r.IP)
		}
		// The triggering call decides the protocol.
		if r.Protocol != "Telnet" {
			t.Errorf("%s: protocol = %q, want Telnet", name, r.Protocol)
		}
	}

	if len(ra.Creds) != 2 || ra.Creds[0].Password != "secret1" {
		t.Errorf("A creds = %+v", ra.Creds)
	}
	for _, cr := range rb.Creds {
		if cr.Password != "" {
			t.Errorf("B must never see a password: %+v", rb.Creds)
		}
	}
	if len(rb.Creds) != 2 || rb.Creds[0].Username != "root" {
		t.Errorf("B creds = %+v", rb.Creds)
	}
	if len(rc.Creds) != 1 || rc.Creds[0].Username != "" || rc.Creds[0].Password != "" {
		t.Errorf("C should have exactly one empty credential: %+v", rc.Creds)
	}

	// Tampering with one backend's data must not affect another's.
	ra.Creds[0].Username = "tampered"
	if rb.Creds[0].Username == "tampered" {
		t.Error("backends share credential memory")
	}

	e := hook.find("report threshold reached")
	if e == nil {
		t.Fatal("missing threshold log")
	}
	if got := e.Data["backends"]; got != "A,B,C" {
		t.Errorf("logged backends = %v, want A,B,C", got)
	}
}

func TestRecordFailure_CredentialCapPerWindow(t *testing.T) {
	f := newFake("A")
	m := newTestManager(maxCredsPerWindow+50, f)
	ip := "192.0.2.50"
	for i := 0; i < maxCredsPerWindow+50; i++ {
		m.RecordFailure(ip, "SSH", fmt.Sprintf("user%d", i), "p")
	}
	r := f.next(t)
	if len(r.Creds) != maxCredsPerWindow {
		t.Errorf("creds = %d, want cap %d", len(r.Creds), maxCredsPerWindow)
	}
}

func TestRecordFailure_ConcurrentSameIPReportsExactlyOnce(t *testing.T) {
	f := newFake("A")
	const threshold, goroutines = 10, 200
	m := newTestManager(threshold, f)

	var wg sync.WaitGroup
	var mu sync.Mutex
	scheduled := 0
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if m.RecordFailure("192.0.2.60", "SSH", fmt.Sprintf("u%d", i), "p") {
				mu.Lock()
				scheduled++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if scheduled != 1 {
		t.Fatalf("%d reports scheduled concurrently, want exactly 1", scheduled)
	}
	f.next(t)
	f.expectNone(t)
}

func TestRecordFailure_ConcurrentManyIPs(t *testing.T) {
	f := newFake("A")
	m := newTestManager(3, f)

	const ips, perIP = 50, 3
	var wg sync.WaitGroup
	for i := 0; i < ips; i++ {
		for j := 0; j < perIP; j++ {
			wg.Add(1)
			go func(i, j int) {
				defer wg.Done()
				m.RecordFailure(fmt.Sprintf("198.51.100.%d", i+1), "SSH", fmt.Sprintf("u%d", j), "p")
			}(i, j)
		}
	}
	wg.Wait()

	seen := map[string]bool{}
	for i := 0; i < ips; i++ {
		seen[f.next(t).IP] = true
	}
	if len(seen) != ips {
		t.Errorf("reports for %d distinct IPs, want %d", len(seen), ips)
	}
}

// ── addCredential ────────────────────────────────────────────────────────────

func TestAddCredential(t *testing.T) {
	var l []Credential
	l = addCredential(l, Credential{Username: "u", Password: "a"})
	l = addCredential(l, Credential{Username: "u", Password: "a"}) // duplicate
	l = addCredential(l, Credential{Username: "u", Password: "b"}) // same user, new password
	l = addCredential(l, Credential{Username: "v", Password: "a"}) // new user, same password
	if len(l) != 3 {
		t.Fatalf("len = %d, want 3: %+v", len(l), l)
	}
	if l[0].Password != "a" || l[1].Password != "b" || l[2].Username != "v" {
		t.Errorf("order not preserved: %+v", l)
	}
}

func TestAddCredential_Cap(t *testing.T) {
	var l []Credential
	for i := 0; i < maxCredsPerWindow*3; i++ {
		l = addCredential(l, Credential{Username: fmt.Sprintf("u%d", i)})
	}
	if len(l) != maxCredsPerWindow {
		t.Fatalf("len = %d, want %d", len(l), maxCredsPerWindow)
	}
	// A duplicate of an existing entry is still a no-op at the cap.
	if got := addCredential(l, Credential{Username: "u0"}); len(got) != maxCredsPerWindow {
		t.Error("duplicate at cap changed the list")
	}
}

// ── cleanup ──────────────────────────────────────────────────────────────────

func TestCleanup_RemovesOnlyExpiredState(t *testing.T) {
	hook := captureLogs(t)
	m := stoppable(t, NewManager([]Backend{newFake("A")}, 3, time.Hour, time.Hour, 2*time.Hour))

	now := time.Now()
	m.mu.Lock()
	m.ips["192.0.2.70"] = &abuseIPState{lastSeen: now.Add(-3 * time.Hour)}
	m.ips["192.0.2.71"] = &abuseIPState{lastSeen: now.Add(-3 * time.Hour)}
	m.ips["192.0.2.72"] = &abuseIPState{lastSeen: now.Add(-10 * time.Minute)}
	m.mu.Unlock()

	m.cleanup()

	m.mu.Lock()
	_, expired1 := m.ips["192.0.2.70"]
	_, expired2 := m.ips["192.0.2.71"]
	_, active := m.ips["192.0.2.72"]
	m.mu.Unlock()

	if expired1 || expired2 {
		t.Error("expired state was not removed")
	}
	if !active {
		t.Error("active state was removed")
	}

	e := hook.find("cleanup completed")
	if e == nil {
		t.Fatal("expected cleanup log")
	}
	if e.Data["removed"] != 2 || e.Data["remaining"] != 1 {
		t.Errorf("cleanup log fields = %v, want removed=2 remaining=1", e.Data)
	}
}

func TestCleanup_NothingToRemoveIsSilent(t *testing.T) {
	hook := captureLogs(t)
	m := newTestManager(3, newFake("A"))
	m.mu.Lock()
	m.ips["192.0.2.73"] = &abuseIPState{lastSeen: time.Now()}
	m.mu.Unlock()

	m.cleanup()

	if hook.find("cleanup completed") != nil {
		t.Error("cleanup logged although nothing was removed")
	}
	if len(m.ips) != 1 {
		t.Error("active state removed")
	}
}

func TestCleanupLoop_RunsPeriodically(t *testing.T) {
	m := stoppable(t, NewManager([]Backend{newFake("A")}, 3, time.Hour, 10*time.Millisecond, time.Millisecond))

	m.mu.Lock()
	m.ips["192.0.2.74"] = &abuseIPState{lastSeen: time.Now().Add(-time.Hour)}
	m.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		n := len(m.ips)
		m.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("cleanupLoop never removed the expired entry")
}

func TestNewManager_NoBackendsStartsNoCleanupLoop(t *testing.T) {
	m := NewManager(nil, 3, time.Hour, 5*time.Millisecond, time.Nanosecond)
	m.mu.Lock()
	m.ips["192.0.2.75"] = &abuseIPState{lastSeen: time.Now().Add(-time.Hour)}
	m.mu.Unlock()

	time.Sleep(60 * time.Millisecond)

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.ips) != 1 {
		t.Error("a cleanup loop is running although there are no backends")
	}
}

// ── Setup ────────────────────────────────────────────────────────────────────

func TestSetup_DefaultsWithNothingEnabled(t *testing.T) {
	isolate(t)
	m, fields := Setup(Options{Getenv: env()})

	if m == nil {
		t.Fatal("Setup must always return a Manager")
	}
	if len(m.backends) != 0 {
		t.Errorf("backends = %d, want 0", len(m.backends))
	}
	if len(fields) != 0 {
		t.Errorf("startup fields should be empty when nothing is enabled: %v", fields)
	}
	if m.attemptsLimit != 10 || m.reportEvery != 15*time.Minute ||
		m.cleanupEvery != 30*time.Minute || m.stateExpiry != 2*time.Hour {
		t.Errorf("unexpected defaults: %d %v %v %v", m.attemptsLimit, m.reportEvery, m.cleanupEvery, m.stateExpiry)
	}
	if m.RecordFailure("192.0.2.1", "SSH", "u", "p") {
		t.Error("a manager without backends must not report")
	}
}

func TestSetup_BothBackendsAndSharedSettings(t *testing.T) {
	isolate(t)

	m, fields := Setup(Options{Getenv: env(
		"ABUSEIPDB_ENABLED", "true", "ABUSEIPDB_API_KEY", "SECRET-ABUSEIPDB",
		"DSHIELD_ENABLED", "true", "DSHIELD_USERID", "42", "DSHIELD_API_KEY", "SECRET-DSHIELD",
		"ABUSE_REPORT_ATTEMPTS", "7",
		"ABUSE_REPORT_INTERVAL", "20m",
		"ABUSE_CLEANUP_INTERVAL", "1h",
		"ABUSE_STATE_EXPIRY", "3h",
	)})

	t.Cleanup(m.Stop)

	if len(m.backends) != 2 ||
		m.backends[0].Name() != "AbuseIPDB" ||
		m.backends[1].Name() != "DShield" {
		t.Fatalf("backends = %v", m.backends)
	}

	if m.attemptsLimit != 7 ||
		m.reportEvery != 20*time.Minute ||
		m.cleanupEvery != time.Hour ||
		m.stateExpiry != 3*time.Hour {
		t.Errorf(
			"shared settings not applied: %d %v %v %v",
			m.attemptsLimit,
			m.reportEvery,
			m.cleanupEvery,
			m.stateExpiry,
		)
	}

	// Startup fields now use the hierarchical structure:
	//
	// abuse:
	//   ABUSE_...
	//   abuseipdb:
	//     ABUSEIPDB_...
	//   dshield:
	//     DSHIELD_...
	abuseRaw, ok := fields["abuse"]
	if !ok {
		t.Fatalf("missing abuse startup fields: %v", fields)
	}

	abuse, ok := asFields(abuseRaw)
	if !ok {
		t.Fatalf("fields[abuse] = %T, want map[string]any", abuseRaw)
	}

	// Shared abuse settings remain directly under "abuse".
	if abuse["ABUSE_REPORT_ATTEMPTS"] != 7 ||
		abuse["ABUSE_REPORT_INTERVAL"] != "20m0s" ||
		abuse["ABUSE_CLEANUP_INTERVAL"] != "1h0m0s" ||
		abuse["ABUSE_STATE_EXPIRY"] != "3h0m0s" {
		t.Errorf("shared startup fields wrong: %v", abuse)
	}

	// Backend-specific settings are nested under their backend name.
	abuseIPDBRaw, ok := abuse["abuseipdb"]
	if !ok {
		t.Fatalf("missing abuseipdb startup fields: %v", abuse)
	}

	abuseIPDB, ok := asFields(abuseIPDBRaw)
	if !ok {
		t.Fatalf("fields[abuse][abuseipdb] = %T, want map[string]any", abuseIPDBRaw)
	}

	if abuseIPDB["ABUSEIPDB_ENABLED"] != true {
		t.Errorf("ABUSEIPDB_ENABLED = %v, want true", abuseIPDB["ABUSEIPDB_ENABLED"])
	}

	dshieldRaw, ok := abuse["dshield"]
	if !ok {
		t.Fatalf("missing dshield startup fields: %v", abuse)
	}

	dshield, ok := asFields(dshieldRaw)
	if !ok {
		t.Fatalf("fields[abuse][dshield] = %T, want map[string]any", dshieldRaw)
	}

	if dshield["DSHIELD_ENABLED"] != true ||
		dshield["DSHIELD_USERID"] != "42" {
		t.Errorf("dshield startup fields missing: %v", dshield)
	}

	// Secrets must never appear anywhere in the startup structure.
	var checkNoSecrets func(string, any)
	checkNoSecrets = func(path string, v any) {
		switch x := v.(type) {
		case string:
			if strings.Contains(x, "SECRET") {
				t.Errorf("startup field %s leaks a secret: %q", path, x)
			}

		case map[string]any:
			for k, v := range x {
				checkNoSecrets(path+"."+k, v)
			}

		case logrus.Fields:
			for k, v := range x {
				checkNoSecrets(path+"."+k, v)
			}
		}
	}

	checkNoSecrets("fields", fields)
}

func TestSetup_OnlyOneBackendEnabled(t *testing.T) {
	isolate(t)
	m, fields := Setup(Options{Getenv: env("DSHIELD_ENABLED", "true", "DSHIELD_USERID", "1", "DSHIELD_API_KEY", "k")})
	t.Cleanup(m.Stop)
	if len(m.backends) != 1 || m.backends[0].Name() != "DShield" {
		t.Fatalf("backends = %v", m.backends)
	}
	if _, ok := fields["ABUSEIPDB_ENABLED"]; ok {
		t.Error("disabled backend must not appear in startup fields")
	}
}

func TestSetup_InjectsDependencies(t *testing.T) {
	isolate(t)

	hook := &testHook{}
	l := logrus.New()
	l.SetOutput(&strings.Builder{})
	l.AddHook(hook)

	m, _ := Setup(Options{
		Logger:    logrus.NewEntry(l),
		Getenv:    env("ABUSEIPDB_ENABLED", "true", "ABUSEIPDB_API_KEY", "k"),
		UserAgent: "honeypot/9.9",
	})

	t.Cleanup(m.Stop)
	if userAgent != "honeypot/9.9" {
		t.Errorf("userAgent = %q", userAgent)
	}
	m.RecordFailure("not-an-ip", "SSH", "u", "p")
	if hook.find("invalid IP address") == nil {
		t.Error("injected logger was not used")
	}
}

func TestSetup_ZeroOptionsKeepDefaults(t *testing.T) {
	isolate(t)
	logBefore, uaBefore := logger, userAgent
	m, _ := Setup(Options{})
	if m == nil {
		t.Fatal("nil manager")
	}
	if logger != logBefore || userAgent != uaBefore {
		t.Error("zero Options must not replace existing dependencies")
	}
}

func TestSetup_InvalidSharedSettingsAreFatal(t *testing.T) {
	cases := []struct{ key, value string }{
		{"ABUSE_REPORT_ATTEMPTS", "abc"},
		{"ABUSE_REPORT_ATTEMPTS", "0"},
		{"ABUSE_REPORT_ATTEMPTS", "-3"},
		{"ABUSE_REPORT_INTERVAL", "soon"},
		{"ABUSE_REPORT_INTERVAL", "0s"},
		{"ABUSE_REPORT_INTERVAL", "-5m"},
		{"ABUSE_CLEANUP_INTERVAL", "x"},
		{"ABUSE_CLEANUP_INTERVAL", "0s"},
		{"ABUSE_STATE_EXPIRY", "x"},
		{"ABUSE_STATE_EXPIRY", "-1h"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			isolate(t)
			msg := expectFatal(t, func() { Setup(Options{Getenv: env(tc.key, tc.value)}) })
			if !strings.Contains(msg, tc.key) {
				t.Errorf("fatal message %q does not name %s", msg, tc.key)
			}
		})
	}
}

func TestSetup_BackendMisconfigurationIsFatal(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"abuseipdb without key", []string{"ABUSEIPDB_ENABLED", "true"}, "ABUSEIPDB_API_KEY"},
		{"dshield without anything", []string{"DSHIELD_ENABLED", "true"}, "DSHIELD_USERID"},
		{"dshield without key", []string{"DSHIELD_ENABLED", "true", "DSHIELD_USERID", "1"}, "DSHIELD_API_KEY"},
		{"dshield without userid", []string{"DSHIELD_ENABLED", "true", "DSHIELD_API_KEY", "k"}, "DSHIELD_USERID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolate(t)
			msg := expectFatal(t, func() { Setup(Options{Getenv: env(tc.env...)}) })
			if !strings.Contains(msg, tc.want) {
				t.Errorf("fatal message %q does not mention %s", msg, tc.want)
			}
		})
	}
}

func TestManager_StopEndsCleanupLoop(t *testing.T) {
	m := NewManager([]Backend{newFake("A")}, 3, time.Hour, 5*time.Millisecond, time.Millisecond)

	finished := make(chan struct{})
	go func() { m.Stop(); m.Stop(); close(finished) }() // idempotent
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return")
	}

	// After Stop the manager still works, but nothing cleans up in the background.
	m.mu.Lock()
	m.ips["192.0.2.80"] = &abuseIPState{lastSeen: time.Now().Add(-time.Hour)}
	m.mu.Unlock()
	time.Sleep(40 * time.Millisecond)
	m.mu.Lock()
	n := len(m.ips)
	m.mu.Unlock()
	if n != 1 {
		t.Error("cleanup loop still running after Stop")
	}
	if !m.RecordFailure("192.0.2.81", "SSH", "u", "p") && len(m.ips) < 2 {
		t.Error("RecordFailure should keep working after Stop")
	}
}

func TestManager_StopOnNilAndWithoutLoop(t *testing.T) {
	var nilM *Manager
	nilM.Stop() // must not panic
	NewManager(nil, 1, time.Hour, time.Hour, time.Hour).Stop()
}
