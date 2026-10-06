package abuse

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

type spamhausReq struct {
	method string
	path   string
	header http.Header
	raw    []byte
}

type spamhausServer struct {
	*httptest.Server
	mu     sync.Mutex
	status int
	body   string
	reqs   []spamhausReq
}

func newSpamhausServer(t *testing.T, status int, body string) *spamhausServer {
	t.Helper()
	s := &spamhausServer{status: status, body: body}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.reqs = append(s.reqs, spamhausReq{r.Method, r.URL.Path, r.Header.Clone(), raw})
		status, body := s.status, s.body
		s.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *spamhausServer) only(t *testing.T) spamhausReq {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) != 1 {
		t.Fatalf("got %d requests, want 1", len(s.reqs))
	}
	return s.reqs[0]
}

func newSpamhausForTest(endpoint string, mods ...func(*spamhausBackend)) *spamhausBackend {
	b := &spamhausBackend{
		apiKey:     "SPAMHAUS-SECRET-TOKEN",
		threatType: "attack",
		endpoint:   endpoint,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	for _, m := range mods {
		m(b)
	}
	return b
}

func decodeSubmission(t *testing.T, raw []byte) spamhausSubmission {
	t.Helper()
	var s spamhausSubmission
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("invalid body: %v\n%s", err, raw)
	}
	return s
}

// ── privacy ──────────────────────────────────────────────────────────────────

func TestSpamhaus_SanitizeDropsEverything(t *testing.T) {
	b := newSpamhausForTest("")
	for _, c := range [][2]string{{"root", "hunter2"}, {"", "x"}, {"admin", ""}, {"", ""}} {
		if u, p := b.Sanitize(c[0], c[1]); u != "" || p != "" {
			t.Errorf("Sanitize(%q,%q) = (%q,%q), want nothing retained", c[0], c[1], u, p)
		}
	}
	if b.Name() != "Spamhaus" {
		t.Errorf("Name() = %q", b.Name())
	}
}

func TestSpamhaus_NoUsernamesOrPasswordsOnTheWire(t *testing.T) {
	srv := newSpamhausServer(t, 200, `{"id":"abc"}`)
	b := newSpamhausForTest(srv.URL)

	// Even if credentials were handed to the backend, they must not be transmitted.
	b.Report(Report{IP: "198.51.100.7", Protocol: "SSH", Creds: []Credential{
		{Time: time.Now(), Username: "root", Password: "hunter2"},
		{Time: time.Now(), Username: "uniqueuser42", Password: "uniquepass42"},
	}})

	raw := string(srv.only(t).raw)
	for _, secret := range []string{"root", "hunter2", "uniqueuser42", "uniquepass42"} {
		if strings.Contains(raw, secret) {
			t.Errorf("request body contains %q: %s", secret, raw)
		}
	}
}

func TestSpamhaus_ManagerNeverRetainsCredentials(t *testing.T) {
	captureLogs(t)
	srv := newSpamhausServer(t, 200, `{}`)
	b := newSpamhausForTest(srv.URL)
	m := stoppable(t, NewManager([]Backend{b}, 5, time.Hour, time.Hour, time.Hour))

	m.RecordFailure("203.0.113.50", "SSH", "secretuser", "secretpass")

	_, _, creds, ok := snapshot(m, "203.0.113.50")
	if !ok {
		t.Fatal("no state")
	}
	for _, c := range creds[0] {
		if c.Username != "" || c.Password != "" {
			t.Errorf("manager retained credentials for Spamhaus: %+v", c)
		}
	}
}

// ── request ──────────────────────────────────────────────────────────────────

func TestSpamhaus_ReportRequest(t *testing.T) {
	userAgent = "spam-test/1.0"
	t.Cleanup(func() { userAgent = "ssh-auth-logger" })
	srv := newSpamhausServer(t, 200, `{"id":"b0f6"}`)
	b := newSpamhausForTest(srv.URL + "/portal/api/v1/submissions/add/ip")

	b.Report(Report{IP: "77.91.65.68", Protocol: "SSH"})

	r := srv.only(t)
	if r.method != http.MethodPost || r.path != "/portal/api/v1/submissions/add/ip" {
		t.Errorf("request = %s %s", r.method, r.path)
	}
	if r.header.Get("Authorization") != "Bearer SPAMHAUS-SECRET-TOKEN" ||
		r.header.Get("Content-Type") != "application/json" ||
		r.header.Get("User-Agent") != "spam-test/1.0" {
		t.Errorf("headers = %v", r.header)
	}

	s := decodeSubmission(t, r.raw)
	if s.ThreatType != "attack" || s.Source.Object != "77.91.65.68" {
		t.Errorf("submission = %+v", s)
	}
	if !strings.Contains(string(r.raw), `"source":{"object":"77.91.65.68"}`) {
		t.Errorf("source must be nested as documented: %s", r.raw)
	}

	// Only the three documented fields are sent.
	var generic map[string]any
	_ = json.Unmarshal(r.raw, &generic)
	if len(generic) != 3 {
		t.Errorf("unexpected fields in body: %v", generic)
	}
}

func TestSpamhaus_ConfiguredThreatTypeIsUsed(t *testing.T) {
	srv := newSpamhausServer(t, 200, `{}`)
	b := newSpamhausForTest(srv.URL, func(b *spamhausBackend) { b.threatType = "other-code" })
	b.Report(Report{IP: "198.51.100.8", Protocol: "SSH"})
	if got := decodeSubmission(t, srv.only(t).raw).ThreatType; got != "other-code" {
		t.Errorf("threat_type = %q", got)
	}
}

// ── reason ───────────────────────────────────────────────────────────────────

func TestSpamhaus_ReasonText(t *testing.T) {
	cases := []struct{ proto, ip, want string }{
		{"SSH", "198.51.100.9", "SSH authentication brute-force attempt against GAS85/ssh-auth-logger honeypot from 198.51.100.9"},
		{"Telnet", "2001:db8::1", "Telnet authentication brute-force attempt against GAS85/ssh-auth-logger honeypot from 2001:db8::1"},
		{"", "198.51.100.9", "SSH/Telnet authentication brute-force attempt against GAS85/ssh-auth-logger honeypot from 198.51.100.9"},
	}
	for _, tc := range cases {
		if got := reasonFor(tc.proto, tc.ip); got != tc.want {
			t.Errorf("reasonFor(%q,%q) =\n  %q\nwant\n  %q", tc.proto, tc.ip, got, tc.want)
		}
	}
}

func TestSpamhaus_ReasonNeverExceedsLimit(t *testing.T) {
	longestIPv6 := "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"
	for _, ip := range []string{"1.2.3.4", longestIPv6} {
		for _, proto := range []string{"SSH", "Telnet"} {
			if n := len(reasonFor(proto, ip)); n > spamhausMaxReasonLen {
				t.Errorf("normal reason is %d bytes (limit %d)", n, spamhausMaxReasonLen)
			}
		}
	}

	// Pathological protocol value: must be cut on a rune boundary.
	weird := strings.Repeat("é", 400)
	r := reasonFor(weird, "198.51.100.9")
	if len(r) > spamhausMaxReasonLen || !utf8.ValidString(r) {
		t.Errorf("reason: %d bytes, valid=%v", len(r), utf8.ValidString(r))
	}
}

func TestSpamhaus_ReasonOnTheWireRespectsLimit(t *testing.T) {
	srv := newSpamhausServer(t, 200, `{}`)
	newSpamhausForTest(srv.URL).Report(Report{IP: "198.51.100.9", Protocol: strings.Repeat("x", 1000)})
	if n := len(decodeSubmission(t, srv.only(t).raw).Reason); n > spamhausMaxReasonLen {
		t.Errorf("reason on the wire is %d bytes", n)
	}
}

// ── responses ────────────────────────────────────────────────────────────────

func TestSpamhaus_ResponseHandling(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantInfo   string // substring of an info message, "" if none expected
		wantReject bool
	}{
		{"accepted", 200, `{"id":"b0f67e0b","submission_type":"ip"}`, "reported", false},
		{"already reported is not an error", 208, `{"status":208,"message":"submission already reported"}`, "already reported", false},
		{"bad request", 400, `{"status":400,"message":"invalid IP address provided"}`, "", true},
		{"unauthorized", 401, `{"status":401,"message":"user is not authorized"}`, "", true},
		{"forbidden", 403, `forbidden`, "", true},
		{"rate limited", 429, `slow down`, "", true},
		{"server error", 500, `oops`, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hook := captureLogs(t)
			srv := newSpamhausServer(t, tc.status, tc.body)
			newSpamhausForTest(srv.URL).Report(Report{IP: "198.51.100.20", Protocol: "SSH"})

			rejected := hook.find("rejected")
			if tc.wantReject {
				if rejected == nil {
					t.Fatal("expected a rejection warning")
				}
				if rejected.Data["body"] != tc.body || !strings.Contains(fmt.Sprint(rejected.Data["status"]), fmt.Sprint(tc.status)) {
					t.Errorf("fields = %v", rejected.Data)
				}
				if hook.find("IP 198.51.100.20 reported") != nil || hook.find("already reported") != nil {
					t.Error("a rejected report was also logged as success")
				}
			} else {
				if rejected != nil {
					t.Fatalf("unexpected rejection: %v", rejected.Data)
				}
				e := hook.find(tc.wantInfo)
				if e == nil || e.Data["ip"] != "198.51.100.20" {
					t.Fatalf("missing %q log: %+v", tc.wantInfo, e)
				}
			}

			for _, e := range hook.entries {
				for k, v := range e.Data {
					if s, ok := v.(string); ok && strings.Contains(s, "SPAMHAUS-SECRET-TOKEN") {
						t.Errorf("log field %s leaks the token", k)
					}
				}
				if strings.Contains(e.Message, "SPAMHAUS-SECRET-TOKEN") {
					t.Error("log message leaks the token")
				}
			}
		})
	}
}

func TestSpamhaus_AcceptedLogCarriesSubmissionID(t *testing.T) {
	hook := captureLogs(t)
	srv := newSpamhausServer(t, 200, `{"id":"b0f67e0bae18"}`)
	newSpamhausForTest(srv.URL).Report(Report{IP: "198.51.100.21", Protocol: "Telnet"})
	e := hook.find("reported")
	if e == nil || e.Data["id"] != "b0f67e0bae18" || e.Data["protocol"] != "Telnet" {
		t.Fatalf("log = %+v", e)
	}
}

func TestSpamhaus_RejectionBodyIsBounded(t *testing.T) {
	hook := captureLogs(t)
	srv := newSpamhausServer(t, 500, strings.Repeat("x", 100_000))
	newSpamhausForTest(srv.URL).Report(Report{IP: "198.51.100.22", Protocol: "SSH"})
	e := hook.find("rejected")
	if e == nil || len(e.Data["body"].(string)) != 4096 {
		t.Fatalf("body must be capped at 4096 bytes, entry = %+v", e)
	}
}

func TestSpamhaus_TransportErrorIsLogged(t *testing.T) {
	hook := captureLogs(t)
	srv := newSpamhausServer(t, 200, `{}`)
	url := srv.URL
	srv.Close()
	newSpamhausForTest(url).Report(Report{IP: "198.51.100.23", Protocol: "SSH"})
	if hook.find("request failed") == nil {
		t.Error("expected an error log")
	}
}

func TestSpamhaus_InvalidEndpointIsLogged(t *testing.T) {
	hook := captureLogs(t)
	newSpamhausForTest("://bad").Report(Report{IP: "198.51.100.24", Protocol: "SSH"})
	if hook.find("failed to create request") == nil {
		t.Error("expected an error log")
	}
}

// ── constructor ──────────────────────────────────────────────────────────────

func TestNewSpamhausFromEnv_DisabledByDefault(t *testing.T) {
	useEnv(t)
	if b, f := newSpamhausFromEnv(); b != nil || f != nil {
		t.Fatalf("expected (nil, nil), got (%v, %v)", b, f)
	}
}

func TestNewSpamhausFromEnv_Defaults(t *testing.T) {
	useEnv(t, "SPAMHAUS_ENABLED", "true", "SPAMHAUS_API_KEY", "TOPSECRET")
	be, fields := newSpamhausFromEnv()
	b := be.(*spamhausBackend)

	if b.apiKey != "TOPSECRET" || b.threatType != "attack" {
		t.Errorf("backend = %+v", b)
	}
	if b.endpoint != spamhausDefaultURL || !strings.HasPrefix(b.endpoint, "https://") ||
		!strings.HasSuffix(b.endpoint, "/submissions/add/ip") {
		t.Errorf("endpoint = %q", b.endpoint)
	}
	if b.httpClient.Timeout != 10*time.Second || b.httpClient.CheckRedirect == nil {
		t.Error("client needs a timeout and must block redirects")
	}

	// newSpamhausFromEnv() returns:
	// map[string]any{
	//     "spamhouse": map[string]any{...},
	// }
	wrapper, ok := asFields(fields)
	if !ok {
		t.Fatalf("fields = %T, want map[string]any", fields)
	}

	spamhausFields, ok := asFields(wrapper["spamhouse"])
	if !ok {
		t.Fatalf("fields[spamhouse] = %T, want map[string]any", wrapper["spamhouse"])
	}

	if spamhausFields["SPAMHAUS_ENABLED"] != true ||
		spamhausFields["SPAMHAUS_THREAT_TYPE"] != "attack" {
		t.Errorf("fields[spamhouse] = %v", spamhausFields)
	}

	for k, v := range spamhausFields {
		if s, ok := v.(string); ok && strings.Contains(s, "TOPSECRET") {
			t.Errorf("startup field %s leaks the API key", k)
		}
	}
}

func TestNewSpamhausFromEnv_ThreatTypeOverrideIsTrimmed(t *testing.T) {
	useEnv(t, "SPAMHAUS_ENABLED", "true", "SPAMHAUS_API_KEY", "k", "SPAMHAUS_THREAT_TYPE", "  bulletproof ")
	be, _ := newSpamhausFromEnv()
	if got := be.(*spamhausBackend).threatType; got != "bulletproof" {
		t.Errorf("threatType = %q", got)
	}
}

func TestNewSpamhausFromEnv_MissingKeyIsFatal(t *testing.T) {
	useEnv(t, "SPAMHAUS_ENABLED", "true")
	msg := expectFatal(t, func() { newSpamhausFromEnv() })
	if !strings.Contains(msg, "SPAMHAUS_API_KEY") {
		t.Errorf("message = %q", msg)
	}
}

func TestNewSpamhausFromEnv_NeverFollowsRedirects(t *testing.T) {
	useEnv(t, "SPAMHAUS_ENABLED", "true", "SPAMHAUS_API_KEY", "k")
	hook := captureLogs(t)

	target := newSpamhausServer(t, 200, `{}`)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	be, _ := newSpamhausFromEnv()
	b := be.(*spamhausBackend)
	b.endpoint = redirector.URL
	b.Report(Report{IP: "198.51.100.30", Protocol: "SSH"})

	target.mu.Lock()
	defer target.mu.Unlock()
	if len(target.reqs) != 0 {
		t.Fatal("redirect followed: the bearer token would be sent to another host")
	}
	if hook.find("rejected") == nil {
		t.Error("a redirect response should be reported as a rejection")
	}
}

// ── integration with manager / Setup ─────────────────────────────────────────

func TestSpamhaus_EndToEndThroughManager(t *testing.T) {
	hook := captureLogs(t)
	srv := newSpamhausServer(t, 200, `{"id":"e2e"}`)
	m := stoppable(t, NewManager([]Backend{newSpamhausForTest(srv.URL)}, 2, time.Hour, time.Hour, time.Hour))

	m.RecordFailure("203.0.113.60", "Telnet", "root", "pw")
	if !m.RecordFailure("203.0.113.60", "Telnet", "admin", "pw2") {
		t.Fatal("expected a report at the threshold")
	}

	hook.waitFor(t, "IP 203.0.113.60 reported")
	s := decodeSubmission(t, srv.only(t).raw)
	if s.Source.Object != "203.0.113.60" || s.ThreatType != "attack" ||
		!strings.HasPrefix(s.Reason, "Telnet authentication brute-force attempt") {
		t.Errorf("submission = %+v", s)
	}
	if raw := string(srv.only(t).raw); strings.Contains(raw, "root") || strings.Contains(raw, "pw") {
		t.Errorf("credentials leaked: %s", raw)
	}
}

func TestSetup_SpamhausRegistered(t *testing.T) {
	isolate(t)

	m, fields := Setup(Options{
		Getenv: env(
			"SPAMHAUS_ENABLED", "true",
			"SPAMHAUS_API_KEY", "k",
		),
	})
	t.Cleanup(m.Stop)

	if len(m.backends) != 1 || m.backends[0].Name() != "Spamhaus" {
		t.Fatalf("backends = %v", m.backends)
	}

	// Setup() returns:
	// map[string]any{
	//     "abuse": map[string]any{
	//         "ABUSE_REPORT_ATTEMPTS": 10,
	//         ...
	//         "spamhouse": map[string]any{...},
	//     },
	// }
	root, ok := asFields(fields)
	if !ok {
		t.Fatalf("fields = %T, want map[string]any", fields)
	}

	abuseFields, ok := asFields(root["abuse"])
	if !ok {
		t.Fatalf("fields[abuse] = %T, want map[string]any", root["abuse"])
	}

	if abuseFields["ABUSE_REPORT_ATTEMPTS"] != 10 {
		t.Errorf("shared startup fields = %v", abuseFields)
	}

	spamhausFields, ok := asFields(abuseFields["spamhouse"])
	if !ok {
		t.Fatalf(
			"fields[abuse][spamhouse] = %T, want map[string]any",
			abuseFields["spamhouse"],
		)
	}

	if spamhausFields["SPAMHAUS_ENABLED"] != true ||
		spamhausFields["SPAMHAUS_THREAT_TYPE"] != "attack" {
		t.Errorf("backend startup fields = %v", spamhausFields)
	}
}
