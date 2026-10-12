package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// freshStats swaps the global counters for new ones for the duration of the test.
func freshStats(t *testing.T) *appStats {
	t.Helper()
	old := stats
	stats = &appStats{started: time.Now()}
	t.Cleanup(func() { stats = old })
	return stats
}

func TestStats_TelnetCountsConnectionAndPasswordAttempt(t *testing.T) {
	s := freshStats(t)
	addr := startTelnetServer(t)
	doTelnetLogin(t, addr, "root", "123456")

	if got := s.telnetConnections.Load(); got != 1 {
		t.Errorf("telnetConnections = %d, want 1", got)
	}
	if got := s.telnetPasswords.Load(); got != 1 {
		t.Errorf("telnetPasswords = %d, want 1", got)
	}
	if s.sshPasswords.Load() != 0 || s.sshKeys.Load() != 0 {
		t.Error("SSH counters must stay 0 for a Telnet login")
	}
}

func TestStats_SSHPasswordAndKeyAttemptsAreCountedSeparately(t *testing.T) {
	s := freshStats(t)
	signer, err := getHostKeySigner("stats-client", "ed25519")
	if err != nil {
		t.Fatal(err)
	}
	addr := startSSHServer(t)

	// The honeypot drops a few connections at random, so assert on ">=" and on the other counter staying 0.
	dialSSH(addr, sshClientCfg("root", ssh.Password("toor")))
	if got := s.sshPasswords.Load(); got < 1 {
		t.Errorf("sshPasswords = %d, want >= 1", got)
	}
	if got := s.sshKeys.Load(); got != 0 {
		t.Errorf("sshKeys = %d after a password-only login, want 0", got)
	}

	dialSSH(addr, sshClientCfg("admin", ssh.PublicKeys(signer)))
	if got := s.sshKeys.Load(); got < 1 {
		t.Errorf("sshKeys = %d, want >= 1", got)
	}
	if got := s.telnetPasswords.Load(); got != 0 {
		t.Errorf("telnetPasswords = %d, want 0", got)
	}
}

func TestStats_ShutdownLineContainsAllCounters(t *testing.T) {
	// LOG_FILTER must not be able to strip the statistics.
	oldAllowed := allowedLogFields
	allowedLogFields = map[string]bool{"msg": true}
	defer func() { allowedLogFields = oldAllowed }()

	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	s := &appStats{started: start}
	s.sshConnections.Store(7)
	s.telnetConnections.Store(5)
	s.sshPasswords.Store(11)
	s.telnetPasswords.Store(4)
	s.sshKeys.Store(3)

	reports := installReporter(t, 1, nil)
	abuseReporter.RecordFailure("203.0.113.9", "SSH", "root", "x")
	waitReport(t, reports)

	var buf bytes.Buffer
	logShutdownStats(&buf, s, abuseReporter, "terminated", start.Add(90*time.Minute+30*time.Second))

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
	if out["signal"] != "terminated" {
		t.Errorf("signal = %v", out["signal"])
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
	logShutdownStats(&buf, &appStats{started: time.Now()}, nil, "interrupt", time.Now())
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
	sigs := notifyShutdown() // registered before the signal is sent, so the test process survives it
	go func() {
		handleShutdown(sigs, &buf, &appStats{started: time.Now()}, nil, func(c int) { exited <- c })
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
		t.Fatal("handleShutdown did not react to SIGTERM")
	}
}
