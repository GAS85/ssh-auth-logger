package common

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testSnapshot() Snapshot {
	s := NewStats()
	s.SSHConnections.Store(3)
	s.TelnetConnections.Store(2)
	s.DroppedConnections.Store(1)
	s.OpenSSH.Store(2)
	s.OpenTelnet.Store(1)
	return s.Snapshot("ssh-auth-logger", nil, time.Now())
}

func TestStatsHandler_ReturnsLiveJSON(t *testing.T) {
	s := NewStats()
	h := StatsHandler(func() Snapshot { return s.Snapshot("p", nil, time.Now()) }, "")

	get := func() map[string]any {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
		if rec.Code != 200 {
			t.Fatalf("status = %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q", cc)
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, rec.Body.String())
		}
		return out
	}

	if got := get()["openSshConnections"]; got != float64(0) {
		t.Errorf("openSshConnections = %v, want 0", got)
	}
	s.OpenSSH.Add(2)
	s.DroppedConnections.Add(4)
	out := get()
	if out["openSshConnections"] != float64(2) || out["openConnections"] != float64(2) || out["droppedConnections"] != float64(4) {
		t.Errorf("not live: %v", out)
	}
	for _, k := range []string{"product", "startedAt", "uptime", "uptimeSeconds", "connections", "sshConnections", "telnetConnections",
		"openTelnetConnections", "passwordAttempts", "sshPasswordAttempts", "telnetPasswordAttempts", "sshKeyAttempts",
		"reportsTriggered", "reportsSent", "reportsByBackend"} {
		if _, ok := out[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
}

func TestStatsHandler_MethodsAndPaths(t *testing.T) {
	h := StatsHandler(testSnapshot, "")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/stats", nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") == "" {
		t.Errorf("POST: status %d, Allow %q", rec.Code, rec.Header().Get("Allow"))
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/stats", nil))
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Errorf("HEAD: status %d, body %d bytes", rec.Code, rec.Body.Len())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/other", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("/other: status %d, want 404", rec.Code)
	}
}

func TestStatsHandler_BearerToken(t *testing.T) {
	h := StatsHandler(testSnapshot, "s3cret")
	cases := []struct {
		auth string
		want int
	}{
		{"", 401}, {"Bearer wrong", 401}, {"s3cret", 401}, {"Basic s3cret", 401},
		{"Bearer s3cret", 200}, {"bearer s3cret", 200},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/stats", nil)
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("Authorization %q: status %d, want %d", c.auth, rec.Code, c.want)
		}
	}
}

func TestServeStats_RealListener(t *testing.T) {
	srv, addr, err := ServeStats("127.0.0.1:0", StatsHandler(testSnapshot, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	resp, err := http.Get("http://" + addr.String() + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if resp.StatusCode != 200 || json.Unmarshal(body, &out) != nil || out["openTelnetConnections"] != float64(1) {
		t.Errorf("status %d, body %s", resp.StatusCode, body)
	}
}

func TestServeStats_BadAddress(t *testing.T) {
	if _, _, err := ServeStats("256.0.0.1:99999", http.NotFoundHandler()); err == nil {
		t.Error("expected an error for an invalid address")
	}
	srv, addr, err := ServeStats("127.0.0.1:0", http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if _, _, err := ServeStats(addr.String(), http.NotFoundHandler()); err == nil {
		t.Error("expected an error for an address already in use")
	}
}
