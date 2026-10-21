package main

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/GAS85/ssh-auth-logger/internal/common"
	"golang.org/x/crypto/ssh"
)

// freshStats swaps the global counters for new ones for the duration of the test.
func freshStats(t *testing.T) *common.Stats {
	t.Helper()
	old := stats
	stats = common.NewStats()
	t.Cleanup(func() { stats = old })
	return stats
}

func TestStats_TelnetCountsConnectionAndPasswordAttempt(t *testing.T) {
	s := freshStats(t)
	addr := startTelnetServer(t)
	doTelnetLogin(t, addr, "root", "123456")

	if got := s.TelnetConnections.Load(); got != 1 {
		t.Errorf("telnetConnections = %d, want 1", got)
	}
	if got := s.TelnetPasswords.Load(); got != 1 {
		t.Errorf("telnetPasswords = %d, want 1", got)
	}
	if s.SSHPasswords.Load() != 0 || s.SSHKeys.Load() != 0 {
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
	if got := s.SSHPasswords.Load(); got < 1 {
		t.Errorf("sshPasswords = %d, want >= 1", got)
	}
	if got := s.SSHKeys.Load(); got != 0 {
		t.Errorf("sshKeys = %d after a password-only login, want 0", got)
	}

	dialSSH(addr, sshClientCfg("admin", ssh.PublicKeys(signer)))
	if got := s.SSHKeys.Load(); got < 1 {
		t.Errorf("sshKeys = %d, want >= 1", got)
	}
	if got := s.TelnetPasswords.Load(); got != 0 {
		t.Errorf("telnetPasswords = %d, want 0", got)
	}
}

func TestStats_OpenTelnetConnectionsGauge(t *testing.T) {
	s := freshStats(t)
	addr := startTelnetServer(t)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitFor(t, "OpenTelnet == 1", func() bool { return s.OpenTelnet.Load() == 1 })

	conn.Close()
	waitFor(t, "OpenTelnet back to 0", func() bool { return s.OpenTelnet.Load() == 0 })
	if got := s.TelnetConnections.Load(); got != 1 {
		t.Errorf("TelnetConnections = %d, want 1", got)
	}
}

func TestStats_OpenSSHConnectionsGauge(t *testing.T) {
	s := freshStats(t)
	addr := startSSHServer(t)

	// ~10% of connections are dropped at once by the simulation, so retry until one stays open.
	var conn net.Conn
	for i := 0; i < 20 && conn == nil; i++ {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if waitUntil(500*time.Millisecond, func() bool { return s.OpenSSH.Load() == 1 }) {
			conn = c
		} else {
			c.Close()
			waitUntil(2*time.Second, func() bool { return s.OpenSSH.Load() == 0 })
		}
	}
	if conn == nil {
		t.Fatal("never saw an open SSH connection")
	}
	defer conn.Close()

	conn.Close()
	waitFor(t, "OpenSSH back to 0", func() bool { return s.OpenSSH.Load() == 0 })
	if got := s.SSHConnections.Load(); got < 1 {
		t.Errorf("SSHConnections = %d, want >= 1", got)
	}
}

func TestStats_SimulatedDropsAreCounted(t *testing.T) {
	s := freshStats(t)
	const n = 300
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		srv, cli := net.Pipe()
		cli.Close() // the handshake of a non-dropped connection fails at once
		cfg := ssh.ServerConfig{NoClientAuth: false}
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleConnection(srv, &cfg)
		}()
	}
	wg.Wait()

	// Each connection is dropped with probability 1/10: 0 or more than 100 of 300 is practically impossible.
	if d := s.DroppedConnections.Load(); d == 0 || d > 100 {
		t.Errorf("DroppedConnections = %d of %d, want roughly 30", d, n)
	}
}

func waitUntil(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	if !waitUntil(5*time.Second, cond) {
		t.Fatalf("timed out waiting for: %s", what)
	}
}
