package common

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/GAS85/ssh-auth-logger/internal/abuse"
	"github.com/sirupsen/logrus"
)

type sinkBackend struct{ ch chan abuse.Report }

func (b *sinkBackend) Name() string                          { return "test" }
func (b *sinkBackend) Sanitize(u, p string) (string, string) { return u, p }
func (b *sinkBackend) Report(r abuse.Report)                 { b.ch <- r }

func TestStats_ShutdownLineContainsAllCounters(t *testing.T) {
	// A LOG_FILTER formatter on the global logger must not be able to strip the statistics.
	logrus.SetFormatter(&FilteredJSONFormatter{Allowed: map[string]bool{"msg": true}})
	defer logrus.SetFormatter(&logrus.JSONFormatter{})

	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	s := &Stats{Started: start}
	s.SSHConnections.Store(7)
	s.TelnetConnections.Store(5)
	s.SSHPasswords.Store(11)
	s.TelnetPasswords.Store(4)
	s.SSHKeys.Store(3)

	ch := make(chan abuse.Report, 4)
	m := abuse.NewManager([]abuse.Backend{&sinkBackend{ch: ch}}, 1, time.Hour, time.Hour, time.Hour)
	defer m.Stop()
	m.RecordFailure("203.0.113.9", "SSH", "root", "x")
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for report")
	}

	var buf bytes.Buffer
	LogShutdownStats(&buf, "ssh-auth-logger", s, m, "terminated", start.Add(90*time.Minute+30*time.Second))

	var out map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &out); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, buf.String())
	}
	want := map[string]float64{
		"connections": 12, "sshConnections": 7, "telnetConnections": 5,
		"passwordAttempts": 15, "sshPasswordAttempts": 11, "telnetPasswordAttempts": 4,
		"sshKeyAttempts": 3, "reportsTriggered": 1, "reportsSent": 1,
		"uptimeSeconds": 5430,
	}
	for k, v := range want {
		if got, ok := out[k].(float64); !ok || got != v {
			t.Errorf("%s = %v, want %v", k, out[k], v)
		}
	}
	if out["uptime"] != "1h30m30s" {
		t.Errorf("uptime = %v, want 1h30m30s", out["uptime"])
	}
	if out["signal"] != "terminated" || out["product"] != "ssh-auth-logger" {
		t.Errorf("signal/product = %v / %v", out["signal"], out["product"])
	}
	by, _ := out["reportsByBackend"].(map[string]any)
	if by["test"] != float64(1) {
		t.Errorf("reportsByBackend = %v, want test:1", out["reportsByBackend"])
	}
	if !strings.Contains(buf.String(), "Shutting down") {
		t.Errorf("missing message: %s", buf.String())
	}
}

func TestStats_ShutdownWithoutReporter(t *testing.T) {
	var buf bytes.Buffer
	LogShutdownStats(&buf, "x", NewStats(), nil, "interrupt", time.Now())
	var out map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &out); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if out["reportsSent"] != float64(0) {
		t.Errorf("reportsSent = %v, want 0", out["reportsSent"])
	}
}

func TestStats_HandleShutdownOnSIGTERM(t *testing.T) {
	var buf bytes.Buffer
	exited := make(chan int, 1)
	sigs := NotifyShutdown() // registered before the signal is sent, so the test process survives it
	go func() {
		HandleShutdown(sigs, &buf, "x", NewStats(), nil, func(c int) { exited <- c })
	}()

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-exited:
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
		if !strings.Contains(buf.String(), "Shutting down") || !strings.Contains(buf.String(), "terminated") {
			t.Errorf("unexpected output: %s", buf.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("HandleShutdown did not react to SIGTERM")
	}
}
