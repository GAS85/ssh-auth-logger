package abuse

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type recordedRequest struct {
	method string
	url    string
	header http.Header
	form   url.Values
}

// recorder is a fake transport that records requests and answers with a fixed status/body.
type recorder struct {
	mu     sync.Mutex
	reqs   []recordedRequest
	status int
	body   string
	err    error
}

func newRecorder(status int, body string) *recorder { return &recorder{status: status, body: body} }

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(req.Body)
	form, _ := url.ParseQuery(string(raw))

	r.mu.Lock()
	r.reqs = append(r.reqs, recordedRequest{req.Method, req.URL.String(), req.Header.Clone(), form})
	status, body, err := r.status, r.body, r.err
	r.mu.Unlock()

	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}, nil
}

func (r *recorder) only(t *testing.T) recordedRequest {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.reqs) != 1 {
		t.Fatalf("got %d requests, want 1", len(r.reqs))
	}
	return r.reqs[0]
}

func newAbuseIPDBForTest(rt http.RoundTripper, mods ...func(*abuseIPDBBackend)) *abuseIPDBBackend {
	b := &abuseIPDBBackend{
		apiKey:           "test-api-key",
		sshCategories:    "18,22",
		telnetCategories: "14,18,23",
		httpClient:       &http.Client{Transport: rt},
	}
	for _, m := range mods {
		m(b)
	}
	return b
}

func creds(pairs ...string) []Credential {
	var out []Credential
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, Credential{Time: time.Now(), Username: pairs[i], Password: pairs[i+1]})
	}
	return out
}

// ── Sanitize ─────────────────────────────────────────────────────────────────

func TestAbuseIPDB_Sanitize(t *testing.T) {
	hash := sha1Hex("hunter2")[:8]
	cases := []struct {
		name                      string
		clearUser, clearPW, hashd bool
		inUser, inPW              string
		wantUser, wantPW          string
	}{
		{"everything off", false, false, false, "root", "hunter2", "", ""},
		{"clear username only", true, false, false, "root", "hunter2", "root", ""},
		{"clear password only", false, true, false, "root", "hunter2", "", "hunter2"},
		{"hashed password", false, false, true, "root", "hunter2", "", hash},
		{"hashed wins over clear flag", false, true, true, "root", "hunter2", "", hash},
		{"all on (hashed still wins)", true, true, true, "root", "hunter2", "root", hash},
		{"empty password stays empty (clear)", true, true, false, "root", "", "root", ""},
		{"empty password is not hashed", true, false, true, "root", "", "root", ""},
		{"public key attempt has no password", true, false, true, "admin", "", "admin", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newAbuseIPDBForTest(nil, func(b *abuseIPDBBackend) {
				b.reportClearUsername = tc.clearUser
				b.reportClearPassword = tc.clearPW
				b.reportHashedPassword = tc.hashd
			})
			u, p := b.Sanitize(tc.inUser, tc.inPW)
			if u != tc.wantUser || p != tc.wantPW {
				t.Errorf("Sanitize(%q,%q) = (%q,%q), want (%q,%q)", tc.inUser, tc.inPW, u, p, tc.wantUser, tc.wantPW)
			}
		})
	}
}

func TestAbuseIPDB_HashedPasswordIsEightHexCharPrefix(t *testing.T) {
	b := newAbuseIPDBForTest(nil, func(b *abuseIPDBBackend) { b.reportHashedPassword = true })
	_, p := b.Sanitize("u", "whatever")
	if len(p) != 8 {
		t.Fatalf("hash prefix length = %d, want 8", len(p))
	}
	if !strings.HasPrefix(sha1Hex("whatever"), p) {
		t.Error("reported value is not a prefix of the SHA-1")
	}
}

// ── categoriesFor ────────────────────────────────────────────────────────────

func TestAbuseIPDB_CategoriesFor(t *testing.T) {
	b := newAbuseIPDBForTest(nil)
	cases := map[string]string{
		"SSH": "18,22", "ssh": "18,22",
		"Telnet": "14,18,23", "telnet": "14,18,23", "TELNET": "14,18,23",
		"": "18,22", "something-else": "18,22",
	}
	for proto, want := range cases {
		if got := b.categoriesFor(proto); got != want {
			t.Errorf("categoriesFor(%q) = %q, want %q", proto, got, want)
		}
	}
}

func TestAbuseIPDB_Name(t *testing.T) {
	if got := newAbuseIPDBForTest(nil).Name(); got != "AbuseIPDB" {
		t.Errorf("Name() = %q", got)
	}
}

// ── Report: request shape ────────────────────────────────────────────────────

func TestAbuseIPDB_ReportRequest(t *testing.T) {
	rec := newRecorder(200, `{}`)
	b := newAbuseIPDBForTest(rec, func(b *abuseIPDBBackend) { b.reportClearUsername = true; b.reportClearPassword = true })

	before := time.Now().UTC().Add(-2 * time.Second)
	b.Report(Report{IP: "192.0.2.50", Protocol: "SSH", Creds: creds("root", "pw1", "admin", "pw2")})
	after := time.Now().UTC().Add(2 * time.Second)

	req := rec.only(t)
	if req.method != http.MethodPost || req.url != "https://api.abuseipdb.com/api/v2/report" {
		t.Errorf("request = %s %s", req.method, req.url)
	}
	if req.header.Get("Key") != "test-api-key" ||
		req.header.Get("Accept") != "application/json" ||
		req.header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("headers = %v", req.header)
	}
	if req.form.Get("ip") != "192.0.2.50" || req.form.Get("categories") != "18,22" {
		t.Errorf("form = %v", req.form)
	}

	comment := req.form.Get("comment")
	for _, want := range []string{
		"SSH authentication brute-force attempt",
		"192.0.2.50",
		`usernames=["root" "admin"]`,
		`passwords=["pw1" "pw2"]`,
	} {
		if !strings.Contains(comment, want) {
			t.Errorf("comment %q lacks %q", comment, want)
		}
	}

	ts, err := time.Parse(time.RFC3339, req.form.Get("timestamp"))
	if err != nil {
		t.Fatalf("timestamp not RFC3339: %v", err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("timestamp %v not within the last moments", ts)
	}
}

func TestAbuseIPDB_ReportTelnetUsesTelnetCategories(t *testing.T) {
	rec := newRecorder(200, `{}`)
	b := newAbuseIPDBForTest(rec)
	b.Report(Report{IP: "192.0.2.51", Protocol: "Telnet"})

	req := rec.only(t)
	if req.form.Get("categories") != "14,18,23" {
		t.Errorf("categories = %q, want telnet categories", req.form.Get("categories"))
	}
	if !strings.Contains(req.form.Get("comment"), "Telnet authentication brute-force attempt") {
		t.Errorf("comment = %q", req.form.Get("comment"))
	}
}

// ── Report: comment content / privacy ────────────────────────────────────────

func TestAbuseIPDB_CommentContent(t *testing.T) {
	cases := []struct {
		name        string
		mods        func(*abuseIPDBBackend)
		creds       []Credential
		want        []string
		mustNotHave []string
	}{
		{
			name:        "no credential flags: nothing but the headline",
			mods:        func(*abuseIPDBBackend) {},
			creds:       creds("root", "secret"),
			mustNotHave: []string{"root", "secret", "usernames", "passwords"},
		},
		{
			name:        "usernames only",
			mods:        func(b *abuseIPDBBackend) { b.reportClearUsername = true },
			creds:       creds("root", "secret"),
			want:        []string{`usernames=["root"]`},
			mustNotHave: []string{"secret", "passwords"},
		},
		{
			name:  "clear passwords",
			mods:  func(b *abuseIPDBBackend) { b.reportClearPassword = true },
			creds: creds("", "secret"),
			want:  []string{`passwords=["secret"]`},
		},
		{
			name:        "hashed passwords use a distinct label",
			mods:        func(b *abuseIPDBBackend) { b.reportHashedPassword = true },
			creds:       creds("", "deadbeef"),
			want:        []string{`passwords sha1 prefix=["deadbeef"]`},
			mustNotHave: []string{`passwords=[`},
		},
		{
			name:  "duplicates and empty values are skipped",
			mods:  func(b *abuseIPDBBackend) { b.reportClearUsername = true; b.reportClearPassword = true },
			creds: creds("root", "a", "root", "b", "", "a", "admin", ""),
			want:  []string{`usernames=["root" "admin"]`, `passwords=["a" "b"]`},
		},
		{
			name:        "flags off even if the credentials were provided",
			mods:        func(b *abuseIPDBBackend) {},
			creds:       creds("leak-user", "leak-pass"),
			mustNotHave: []string{"leak-user", "leak-pass"},
		},
		{
			name:        "only empty credentials add no fields",
			mods:        func(b *abuseIPDBBackend) { b.reportClearUsername = true; b.reportClearPassword = true },
			creds:       creds("", ""),
			mustNotHave: []string{"usernames", "passwords"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := newRecorder(200, `{}`)
			b := newAbuseIPDBForTest(rec, tc.mods)
			b.Report(Report{IP: "192.0.2.52", Protocol: "SSH", Creds: tc.creds})
			comment := rec.only(t).form.Get("comment")
			for _, w := range tc.want {
				if !strings.Contains(comment, w) {
					t.Errorf("comment %q lacks %q", comment, w)
				}
			}
			for _, n := range tc.mustNotHave {
				if strings.Contains(comment, n) {
					t.Errorf("comment %q must not contain %q", comment, n)
				}
			}
		})
	}
}

func TestAbuseIPDB_CommentIsTruncatedOnRuneBoundary(t *testing.T) {
	rec := newRecorder(200, `{}`)
	b := newAbuseIPDBForTest(rec, func(b *abuseIPDBBackend) { b.reportClearUsername = true })

	var cs []Credential
	for i := 0; i < 300; i++ {
		cs = append(cs, Credential{Username: strings.Repeat("ü", 5) + string(rune('a'+i%26)) + strings.Repeat("€", i%7)})
		cs[i].Username += string(rune(0x4e00 + i)) // make each unique
	}
	b.Report(Report{IP: "192.0.2.53", Protocol: "SSH", Creds: cs})

	comment := rec.only(t).form.Get("comment")
	if len(comment) > abuseIPDBMaxCommentLen {
		t.Errorf("comment is %d bytes, limit %d", len(comment), abuseIPDBMaxCommentLen)
	}
	if !utf8.ValidString(comment) {
		t.Error("truncated comment is not valid UTF-8")
	}
	if !strings.HasPrefix(comment, "SSH authentication brute-force attempt") {
		t.Errorf("headline lost: %q", comment[:60])
	}
}

// ── Report: response handling ────────────────────────────────────────────────

func TestAbuseIPDB_ReportSuccessIsLogged(t *testing.T) {
	hook := captureLogs(t)
	b := newAbuseIPDBForTest(newRecorder(200, `{"data":{}}`))
	b.Report(Report{IP: "192.0.2.54", Protocol: "SSH"})

	e := hook.find("reported")
	if e == nil || e.Data["ip"] != "192.0.2.54" || e.Data["protocol"] != "SSH" {
		t.Fatalf("success log = %+v", e)
	}
}

func TestAbuseIPDB_ReportRejectionLogsStatusAndBody(t *testing.T) {
	for _, status := range []int{400, 401, 422, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			hook := captureLogs(t)
			b := newAbuseIPDBForTest(newRecorder(status, `{"errors":[{"detail":"nope"}]}`))
			b.Report(Report{IP: "192.0.2.55", Protocol: "Telnet"})

			e := hook.find("rejected")
			if e == nil {
				t.Fatal("no rejection log")
			}
			if e.Data["body"] != `{"errors":[{"detail":"nope"}]}` {
				t.Errorf("body = %v", e.Data["body"])
			}
			if e.Data["protocol"] != "Telnet" || e.Data["ip"] != "192.0.2.55" {
				t.Errorf("fields = %v", e.Data)
			}
			if hook.find("IP 192.0.2.55 reported") != nil {
				t.Error("a rejected report was logged as success")
			}
		})
	}
}

func TestAbuseIPDB_RejectionBodyIsBounded(t *testing.T) {
	hook := captureLogs(t)
	b := newAbuseIPDBForTest(newRecorder(500, strings.Repeat("x", 100_000)))
	b.Report(Report{IP: "192.0.2.56", Protocol: "SSH"})

	e := hook.find("rejected")
	if e == nil {
		t.Fatal("no rejection log")
	}
	if n := len(e.Data["body"].(string)); n != 4096 {
		t.Errorf("logged body is %d bytes, want it capped at 4096", n)
	}
}

func TestAbuseIPDB_TransportErrorIsLoggedNotPanicked(t *testing.T) {
	hook := captureLogs(t)
	rec := newRecorder(200, "")
	rec.err = errors.New("connection refused")
	b := newAbuseIPDBForTest(rec)

	b.Report(Report{IP: "192.0.2.57", Protocol: "SSH"})

	e := hook.find("request failed")
	if e == nil {
		t.Fatal("no error log")
	}
	if e.Data["ip"] != "192.0.2.57" {
		t.Errorf("fields = %v", e.Data)
	}
}

// ── Constructor ──────────────────────────────────────────────────────────────

func TestNewAbuseIPDBFromEnv_DisabledByDefault(t *testing.T) {
	useEnv(t)
	b, fields := newAbuseIPDBFromEnv()
	if b != nil || fields != nil {
		t.Fatalf("expected (nil, nil), got (%v, %v)", b, fields)
	}
}

func TestNewAbuseIPDBFromEnv_Defaults(t *testing.T) {
	useEnv(t, "ABUSEIPDB_ENABLED", "true", "ABUSEIPDB_API_KEY", "k")
	be, fields := newAbuseIPDBFromEnv()
	b := be.(*abuseIPDBBackend)

	if b.apiKey != "k" || b.sshCategories != "18,22" || b.telnetCategories != "14,18,23" {
		t.Errorf("backend = %+v", b)
	}
	if b.reportClearUsername || b.reportClearPassword || !b.reportHashedPassword {
		t.Errorf("privacy defaults wrong: user=%v clearPW=%v hashed=%v",
			b.reportClearUsername, b.reportClearPassword, b.reportHashedPassword)
	}
	if b.httpClient == nil || b.httpClient.Timeout != 10*time.Second {
		t.Error("http client with 10s timeout expected")
	}
	if fields["ABUSEIPDB_ENABLED"] != true || fields["ABUSEIPDB_REPORT_HASHED_PASSWORD"] != true {
		t.Errorf("fields = %v", fields)
	}
	for k, v := range fields {
		if v == "k" {
			t.Errorf("field %s leaks the API key", k)
		}
	}
}

func TestNewAbuseIPDBFromEnv_Overrides(t *testing.T) {
	useEnv(t,
		"ABUSEIPDB_ENABLED", "yes", "ABUSEIPDB_API_KEY", "k",
		"ABUSEIPDB_SSH_CATEGORIES", "18",
		"ABUSEIPDB_TELNET_CATEGORIES", "14",
		"ABUSEIPDB_REPORT_CLEAR_USERNAME", "true",
		"ABUSEIPDB_REPORT_CLEAR_PASSWORD", "true",
		"ABUSEIPDB_REPORT_HASHED_PASSWORD", "false",
	)
	be, fields := newAbuseIPDBFromEnv()
	b := be.(*abuseIPDBBackend)

	if b.sshCategories != "18" || b.telnetCategories != "14" {
		t.Errorf("categories = %q / %q", b.sshCategories, b.telnetCategories)
	}
	if !b.reportClearUsername || !b.reportClearPassword || b.reportHashedPassword {
		t.Errorf("flags wrong: %+v", b)
	}
	if fields["ABUSEIPDB_SSH_CATEGORIES"] != "18" || fields["ABUSEIPDB_REPORT_CLEAR_PASSWORD"] != true {
		t.Errorf("fields = %v", fields)
	}
}

func TestNewAbuseIPDBFromEnv_HashedOverridesClearPassword(t *testing.T) {
	useEnv(t, "ABUSEIPDB_ENABLED", "true", "ABUSEIPDB_API_KEY", "k",
		"ABUSEIPDB_REPORT_CLEAR_PASSWORD", "true", "ABUSEIPDB_REPORT_HASHED_PASSWORD", "true")
	be, fields := newAbuseIPDBFromEnv()
	b := be.(*abuseIPDBBackend)

	if b.reportClearPassword || !b.reportHashedPassword {
		t.Fatalf("hashed must override clear: clear=%v hashed=%v", b.reportClearPassword, b.reportHashedPassword)
	}
	if fields["ABUSEIPDB_REPORT_CLEAR_PASSWORD"] != false {
		t.Errorf("startup log must show the effective clear-password value, got %v", fields["ABUSEIPDB_REPORT_CLEAR_PASSWORD"])
	}
	if _, p := b.Sanitize("u", "secret"); p == "secret" {
		t.Error("cleartext password would be transmitted")
	}
}

func TestNewAbuseIPDBFromEnv_MissingKeyIsFatal(t *testing.T) {
	useEnv(t, "ABUSEIPDB_ENABLED", "true")
	msg := expectFatal(t, func() { newAbuseIPDBFromEnv() })
	if !strings.Contains(msg, "ABUSEIPDB_API_KEY") {
		t.Errorf("message = %q", msg)
	}
}
