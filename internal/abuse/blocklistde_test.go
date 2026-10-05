package abuse

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func newBlocklistDeForTest(rt http.RoundTripper, mods ...func(*blocklistDeBackend)) *blocklistDeBackend {
	b := &blocklistDeBackend{
		server:              "honeypot@example.org",
		apiKey:              "SECRET-API-KEY",
		sshService:          "ssh",
		reportClearUsername: true,
		endpoint:            "https://reports.test/en/httpreports.html",
		httpClient:          &http.Client{Transport: rt},
	}
	for _, m := range mods {
		m(b)
	}
	return b
}

const blOK = `{"status":"success","error":0}`

// ── Sanitize / serviceFor ────────────────────────────────────────────────────

func TestBlocklistDe_Sanitize(t *testing.T) {
	hash := sha1Hex("hunter2")[:8]
	cases := []struct {
		name                      string
		clearUser, clearPW, hashd bool
		wantUser, wantPW          string
	}{
		{"nothing", false, false, false, "", ""},
		{"username only", true, false, false, "root", ""},
		{"clear password", true, true, false, "root", "hunter2"},
		{"hashed password", false, false, true, "", hash},
		{"hashed beats clear", true, true, true, "root", hash},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newBlocklistDeForTest(nil, func(b *blocklistDeBackend) {
				b.reportClearUsername, b.reportClearPassword, b.reportHashedPassword = tc.clearUser, tc.clearPW, tc.hashd
			})
			u, p := b.Sanitize("root", "hunter2")
			if u != tc.wantUser || p != tc.wantPW {
				t.Errorf("got (%q,%q), want (%q,%q)", u, p, tc.wantUser, tc.wantPW)
			}
		})
	}
	b := newBlocklistDeForTest(nil, func(b *blocklistDeBackend) { b.reportHashedPassword = true })
	if _, p := b.Sanitize("u", ""); p != "" {
		t.Error("an empty password must not be hashed")
	}
	if b.Name() != "blocklist.de" {
		t.Errorf("Name() = %q", b.Name())
	}
}

func TestBlocklistDe_ServiceFor(t *testing.T) {
	b := newBlocklistDeForTest(nil, func(b *blocklistDeBackend) { b.telnetService = "" })
	for _, p := range []string{"SSH", "ssh", "", "unknown"} {
		if got := b.serviceFor(p); got != "ssh" {
			t.Errorf("serviceFor(%q) = %q, want ssh", p, got)
		}
	}
	for _, p := range []string{"Telnet", "telnet", "TELNET"} {
		if got := b.serviceFor(p); got != "" {
			t.Errorf("serviceFor(%q) = %q, want empty (not reported unless configured)", p, got)
		}
	}
	b.telnetService = "portflood"
	if got := b.serviceFor("Telnet"); got != "portflood" {
		t.Errorf("configured telnet service not used: %q", got)
	}
}

// ── Report: request ──────────────────────────────────────────────────────────

func TestBlocklistDe_ReportRequest(t *testing.T) {
	userAgent = "bl-test/1.0"
	t.Cleanup(func() { userAgent = "ssh-auth-logger" })
	rec := newRecorder(200, blOK)
	b := newBlocklistDeForTest(rec)

	b.Report(Report{IP: "77.91.65.68", Protocol: "SSH", Creds: creds("root", "")})

	req := rec.only(t)
	if req.method != http.MethodPost || req.url != "https://reports.test/en/httpreports.html" {
		t.Errorf("request = %s %s", req.method, req.url)
	}
	if strings.Contains(req.url, "SECRET") || strings.Contains(req.url, "?") {
		t.Error("credentials must be in the POST body, never in the URL")
	}
	if req.header.Get("Content-Type") != "application/x-www-form-urlencoded" || req.header.Get("User-Agent") != "bl-test/1.0" {
		t.Errorf("headers = %v", req.header)
	}
	want := map[string]string{
		"server": "honeypot@example.org", "apikey": "SECRET-API-KEY",
		"ip": "77.91.65.68", "service": "ssh", "format": "json",
	}
	for k, v := range want {
		if got := req.form.Get(k); got != v {
			t.Errorf("form[%s] = %q, want %q", k, got, v)
		}
	}
	if !strings.Contains(req.form.Get("logs"), "from 77.91.65.68") {
		t.Errorf("logs = %q", req.form.Get("logs"))
	}
}

func TestBlocklistDe_TelnetNotReportedWithoutService(t *testing.T) {
	hook := captureLogs(t)
	rec := newRecorder(200, blOK)
	b := newBlocklistDeForTest(rec)

	b.Report(Report{IP: "192.0.2.5", Protocol: "Telnet", Creds: creds("root", "")})

	rec.mu.Lock()
	n := len(rec.reqs)
	rec.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d requests sent, want none", n)
	}
	if hook.find("no service configured") == nil {
		t.Error("expected a debug message explaining why nothing was sent")
	}
}

func TestBlocklistDe_TelnetReportedWithConfiguredService(t *testing.T) {
	rec := newRecorder(200, blOK)
	b := newBlocklistDeForTest(rec, func(b *blocklistDeBackend) { b.telnetService = "portflood" })
	b.Report(Report{IP: "192.0.2.6", Protocol: "Telnet", Creds: creds("root", "")})
	if got := rec.only(t).form.Get("service"); got != "portflood" {
		t.Errorf("service = %q", got)
	}
}

// ── buildLogs ────────────────────────────────────────────────────────────────

func TestBlocklistDe_BuildLogsFormat(t *testing.T) {
	b := newBlocklistDeForTest(nil)
	ts := time.Date(2026, 10, 3, 12, 34, 56, 0, time.FixedZone("x", 3600))
	logs := b.buildLogs(Report{IP: "198.51.100.9", Protocol: "SSH", Creds: []Credential{
		{Time: ts, Username: "root", Password: "pw"},
		{Time: ts, Username: "admin"},
	}})

	lines := strings.Split(strings.TrimSuffix(logs, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d: %q", len(lines), logs)
	}
	if !strings.HasPrefix(lines[0], "2026-10-03T11:34:56Z ssh-auth-logger: Failed SSH authentication from 198.51.100.9") {
		t.Errorf("line 0 = %q", lines[0])
	}
	if !strings.Contains(lines[0], `user="root"`) || !strings.Contains(lines[0], `password="pw"`) {
		t.Errorf("line 0 lacks credentials: %q", lines[0])
	}
	if strings.Contains(lines[1], "password") {
		t.Errorf("empty password must not be mentioned: %q", lines[1])
	}
}

func TestBlocklistDe_BuildLogsHashedLabel(t *testing.T) {
	b := newBlocklistDeForTest(nil, func(b *blocklistDeBackend) { b.reportHashedPassword = true })
	logs := b.buildLogs(Report{IP: "198.51.100.9", Protocol: "SSH", Creds: creds("", "deadbeef")})
	if !strings.Contains(logs, `password_sha1_prefix="deadbeef"`) {
		t.Errorf("logs = %q", logs)
	}
}

func TestBlocklistDe_BuildLogsCannotBeForgedByAttackerInput(t *testing.T) {
	b := newBlocklistDeForTest(nil)
	evil := "root\n2026-01-01T00:00:00Z sshd: Accepted password for admin from 9.9.9.9\r\n"
	logs := b.buildLogs(Report{IP: "198.51.100.9", Protocol: "SSH", Creds: []Credential{
		{Time: time.Now(), Username: evil, Password: "p\nq"},
	}})

	if n := strings.Count(logs, "\n"); n != 1 {
		t.Fatalf("one credential must give exactly one line, got %d newlines: %q", n, logs)
	}
	if strings.Contains(logs, "\r") {
		t.Error("raw carriage return in logs")
	}
	if !strings.Contains(logs, `\n`) {
		t.Error("newline in the username should appear escaped")
	}
}

func TestBlocklistDe_BuildLogsLimits(t *testing.T) {
	b := newBlocklistDeForTest(nil)

	long := strings.Repeat("é", 1000)
	one := b.buildLogs(Report{IP: "198.51.100.9", Protocol: "SSH", Creds: creds(long, "")})
	if len(one) > 400 {
		t.Errorf("long username not truncated: %d bytes", len(one))
	}

	var cs []Credential
	for i := 0; i < 500; i++ {
		cs = append(cs, Credential{Time: time.Now(), Username: strings.Repeat("u", 100) + string(rune('a'+i%26)) + strings.Repeat("x", i%50)})
	}
	logs := b.buildLogs(Report{IP: "198.51.100.9", Protocol: "SSH", Creds: cs})
	if len(logs) > blocklistDeMaxLogsLen {
		t.Errorf("logs = %d bytes, limit %d", len(logs), blocklistDeMaxLogsLen)
	}
	if !strings.HasSuffix(logs, "\n") {
		t.Error("output must end on a whole line")
	}
	if len(logs) < blocklistDeMaxLogsLen/2 {
		t.Errorf("suspiciously little output: %d bytes", len(logs))
	}
}

func TestBlocklistDe_BuildLogsWithoutCredentialsStillHasOneLine(t *testing.T) {
	b := newBlocklistDeForTest(nil)
	logs := b.buildLogs(Report{IP: "198.51.100.9", Protocol: "SSH"})
	if strings.Count(logs, "\n") != 1 || !strings.Contains(logs, "from 198.51.100.9") {
		t.Errorf("logs = %q", logs)
	}
}

// ── response parsing ─────────────────────────────────────────────────────────

func TestParseBlocklistDeResponse(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantOK     bool
		wantDetail string
	}{
		{"success with error 0", `{"status":"success","error":0}`, true, ""},
		{"success without error", `{"status":"success"}`, true, ""},
		{"success is case-insensitive", `{"status":"SUCCESS","error":0}`, true, ""},
		{"error 0 without status", `{"error":0}`, true, ""},
		{"error string zero", `{"error":"0"}`, true, ""},
		{"error empty array without status", `{"error":[]}`, true, ""},
		{"error list", `{"status":"error","error":["apikey: Please give the API key"]}`, false, "apikey"},
		{"error string", `{"status":"error","error":"ip: invalid"}`, false, "ip: invalid"},
		{"error status wins over empty list", `{"status":"error","error":[]}`, false, "status=error"},
		{"error status wins over zero", `{"status":"error","error":0}`, false, "status=error"},
		{"nonzero error without status", `{"error":["boom"]}`, false, "boom"},
		{"no information", `{}`, false, "no error message"},
		{"null error", `{"status":"weird","error":null}`, false, "status=weird"},
		{"not json", `<html>Maintenance</html>`, false, "unparseable"},
		{"empty body", ``, false, "unparseable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, detail := parseBlocklistDeResponse([]byte(tc.body))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (detail %q)", ok, tc.wantOK, detail)
			}
			if !strings.Contains(detail, tc.wantDetail) {
				t.Errorf("detail %q lacks %q", detail, tc.wantDetail)
			}
		})
	}
}

func TestParseBlocklistDeResponse_DetailIsBounded(t *testing.T) {
	_, detail := parseBlocklistDeResponse([]byte(`{"status":"error","error":"` + strings.Repeat("x", 5000) + `"}`))
	if len(detail) > 512 {
		t.Errorf("detail is %d bytes", len(detail))
	}
}

// ── Report: outcome handling ─────────────────────────────────────────────────

func TestBlocklistDe_ReportOutcomes(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantOK   bool
		wantWarn string // substring of the error/body field
	}{
		{"accepted", 200, blOK, true, ""},
		{"HTTP 200 but API error", 200, `{"status":"error","error":["apikey: wrong"]}`, false, "apikey: wrong"},
		{"HTTP 200 but unparseable", 200, `<html>oops</html>`, false, "unparseable"},
		{"HTTP 500", 500, `server exploded`, false, "server exploded"},
		{"HTTP 403", 403, `forbidden`, false, "forbidden"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hook := captureLogs(t)
			b := newBlocklistDeForTest(newRecorder(tc.status, tc.body))
			b.Report(Report{IP: "198.51.100.20", Protocol: "SSH", Creds: creds("root", "")})

			success := hook.find("IP 198.51.100.20 reported")
			rejected := hook.find("rejected")

			if tc.wantOK {
				if success == nil || rejected != nil {
					t.Fatalf("success=%v rejected=%v", success, rejected)
				}
				if success.Data["service"] != "ssh" || success.Data["protocol"] != "SSH" {
					t.Errorf("fields = %v", success.Data)
				}
				return
			}
			if rejected == nil {
				t.Fatal("expected a rejection warning")
			}
			if success != nil {
				t.Error("a failed report was also logged as success")
			}
			got := ""
			for _, k := range []string{"error", "body"} {
				if v, ok := rejected.Data[k]; ok {
					got += v.(string)
				}
			}
			if !strings.Contains(got, tc.wantWarn) {
				t.Errorf("warning fields %v lack %q", rejected.Data, tc.wantWarn)
			}
			for _, e := range hook.entries {
				for k, v := range e.Data {
					if s, ok := v.(string); ok && strings.Contains(s, "SECRET-API-KEY") {
						t.Errorf("log field %s leaks the API key", k)
					}
				}
			}
		})
	}
}

func TestBlocklistDe_TransportErrorIsLogged(t *testing.T) {
	hook := captureLogs(t)
	rec := newRecorder(200, "")
	rec.err = http.ErrHandlerTimeout
	newBlocklistDeForTest(rec).Report(Report{IP: "198.51.100.21", Protocol: "SSH"})
	if hook.find("request failed") == nil {
		t.Error("expected an error log")
	}
}

func TestBlocklistDe_InvalidEndpointIsLogged(t *testing.T) {
	hook := captureLogs(t)
	b := newBlocklistDeForTest(nil, func(b *blocklistDeBackend) { b.endpoint = "://bad" })
	b.Report(Report{IP: "198.51.100.22", Protocol: "SSH"})
	if hook.find("failed to create request") == nil {
		t.Error("expected an error log")
	}
}

// ── Constructor ──────────────────────────────────────────────────────────────

func TestNewBlocklistDeFromEnv_DisabledByDefault(t *testing.T) {
	useEnv(t)
	if b, f := newBlocklistDeFromEnv(); b != nil || f != nil {
		t.Fatalf("expected (nil, nil), got (%v, %v)", b, f)
	}
}

func TestNewBlocklistDeFromEnv_Defaults(t *testing.T) {
	useEnv(t, "BLOCKLIST_ENABLED", "true", "BLOCKLIST_SERVER", "me@example.org", "BLOCKLIST_API_KEY", "TOPSECRET")
	be, fields := newBlocklistDeFromEnv()
	b := be.(*blocklistDeBackend)

	if b.server != "me@example.org" || b.apiKey != "TOPSECRET" {
		t.Error("credentials not read")
	}
	if b.sshService != "ssh-auth" || b.telnetService != "bruteforcelogin" {
		t.Errorf("services = %q / %q", b.sshService, b.telnetService)
	}
	if !b.reportClearUsername || b.reportClearPassword || !b.reportHashedPassword {
		t.Errorf("privacy defaults: user=%v pw=%v hashed=%v", b.reportClearUsername, b.reportClearPassword, b.reportHashedPassword)
	}
	if b.endpoint != blocklistDeURL || !strings.HasPrefix(b.endpoint, "https://") {
		t.Errorf("endpoint = %q (must be https)", b.endpoint)
	}
	if b.httpClient.Timeout != 10*time.Second || b.httpClient.CheckRedirect == nil {
		t.Error("client needs a timeout and must block redirects")
	}
	if fields["BLOCKLIST_ENABLED"] != true || fields["BLOCKLIST_SSH_SERVICE"] != "ssh-auth" {
		t.Errorf("fields = %v", fields)
	}
	for k, v := range fields {
		if s, ok := v.(string); ok && (strings.Contains(s, "TOPSECRET") || strings.Contains(s, "me@example.org")) {
			t.Errorf("startup field %s leaks %q", k, s)
		}
	}
}

func TestNewBlocklistDeFromEnv_Overrides(t *testing.T) {
	useEnv(t, "BLOCKLIST_ENABLED", "true", "BLOCKLIST_SERVER", "s", "BLOCKLIST_API_KEY", "k",
		"BLOCKLIST_SSH_SERVICE", "sshd", "BLOCKLIST_TELNET_SERVICE", "portflood",
		"BLOCKLIST_REPORT_CLEAR_USERNAME", "false", "BLOCKLIST_REPORT_CLEAR_PASSWORD", "true", "BLOCKLIST_REPORT_HASHED_PASSWORD", "false")
	be, _ := newBlocklistDeFromEnv()
	b := be.(*blocklistDeBackend)
	if b.sshService != "sshd" || b.telnetService != "portflood" || b.reportClearUsername || !b.reportClearPassword {
		t.Errorf("overrides not applied: %+v", b)
	}
}

func TestNewBlocklistDeFromEnv_HashedOverridesClear(t *testing.T) {
	useEnv(t, "BLOCKLIST_ENABLED", "true", "BLOCKLIST_SERVER", "s", "BLOCKLIST_API_KEY", "k",
		"BLOCKLIST_REPORT_CLEAR_PASSWORD", "true", "BLOCKLIST_REPORT_HASHED_PASSWORD", "true")
	be, fields := newBlocklistDeFromEnv()
	b := be.(*blocklistDeBackend)
	if b.reportClearPassword || !b.reportHashedPassword || fields["BLOCKLIST_REPORT_CLEAR_PASSWORD"] != false {
		t.Fatalf("hashed must override clear: %+v / %v", b, fields)
	}
}

func TestNewBlocklistDeFromEnv_MissingCredentialsAreFatal(t *testing.T) {
	cases := [][]string{
		{"BLOCKLIST_ENABLED", "true"},
		{"BLOCKLIST_ENABLED", "true", "BLOCKLIST_SERVER", "s"},
		{"BLOCKLIST_ENABLED", "true", "BLOCKLIST_API_KEY", "k"},
	}
	for _, kv := range cases {
		useEnv(t, kv...)
		msg := expectFatal(t, func() { newBlocklistDeFromEnv() })
		if !strings.Contains(msg, "BLOCKLIST_SERVER") || !strings.Contains(msg, "BLOCKLIST_API_KEY") {
			t.Errorf("message %q", msg)
		}
	}
}

func TestNewBlocklistDeFromEnv_NeverFollowsRedirects(t *testing.T) {
	useEnv(t, "BLOCKLIST_ENABLED", "true", "BLOCKLIST_SERVER", "s", "BLOCKLIST_API_KEY", "k")
	hook := captureLogs(t)

	var mu sync.Mutex
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { mu.Lock(); hits++; mu.Unlock() }))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	be, _ := newBlocklistDeFromEnv()
	b := be.(*blocklistDeBackend)
	b.endpoint = redirector.URL
	b.Report(Report{IP: "198.51.100.30", Protocol: "SSH", Creds: creds("root", "")})

	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatal("redirect followed: the API key would be sent to another host")
	}
	if hook.find("rejected") == nil {
		t.Error("a redirect response should be reported as a rejection")
	}
}

// ── Integration with the manager / Setup ─────────────────────────────────────

func TestBlocklistDe_EndToEndThroughManager(t *testing.T) {
	hook := captureLogs(t)
	rec := newRecorder(200, blOK)
	b := newBlocklistDeForTest(rec)
	m := stoppable(t, NewManager([]Backend{b}, 2, time.Hour, time.Hour, time.Hour))

	m.RecordFailure("203.0.113.40", "SSH", "root", "pw")
	if !m.RecordFailure("203.0.113.40", "SSH", "admin", "pw2") {
		t.Fatal("expected a report at the threshold")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec.mu.Lock()
		n := len(rec.reqs)
		rec.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Wait for the backend goroutine to finish (it logs last) before inspecting and tearing down.
	hook.waitFor(t, "IP 203.0.113.40 reported")
	req := rec.only(t)
	logs := req.form.Get("logs")
	if req.form.Get("ip") != "203.0.113.40" || !strings.Contains(logs, `user="root"`) || !strings.Contains(logs, `user="admin"`) {
		t.Errorf("form = %v", req.form)
	}
	if strings.Contains(logs, "pw") {
		t.Error("passwords are off by default for blocklist.de and must not be in the logs")
	}
}

func TestSetup_BlocklistDeRegistered(t *testing.T) {
	isolate(t)
	m, fields := Setup(Options{Getenv: env("BLOCKLIST_ENABLED", "true", "BLOCKLIST_SERVER", "s", "BLOCKLIST_API_KEY", "k")})
	t.Cleanup(m.Stop)
	if len(m.backends) != 1 || m.backends[0].Name() != "blocklist.de" {
		t.Fatalf("backends = %v", m.backends)
	}
	if fields["BLOCKLIST_ENABLED"] != true || fields["ABUSE_REPORT_ATTEMPTS"] != 10 {
		t.Errorf("fields = %v", fields)
	}
}

func TestSetup_AllThreeBackendsInOrder(t *testing.T) {
	isolate(t)
	m, _ := Setup(Options{Getenv: env(
		"ABUSEIPDB_ENABLED", "true", "ABUSEIPDB_API_KEY", "k",
		"DSHIELD_ENABLED", "true", "DSHIELD_USERID", "1", "DSHIELD_API_KEY", "k",
		"BLOCKLIST_ENABLED", "true", "BLOCKLIST_SERVER", "s", "BLOCKLIST_API_KEY", "k",
	)})
	t.Cleanup(m.Stop)
	var names []string
	for _, b := range m.backends {
		names = append(names, b.Name())
	}
	if strings.Join(names, ",") != "AbuseIPDB,DShield,blocklist.de" {
		t.Errorf("backends = %v", names)
	}
}
