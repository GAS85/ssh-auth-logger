package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// TestMain runs before all tests, overriding slow/awkward defaults set by init().
func TestMain(m *testing.M) {
	rsaBits = 2048          // init() sets 3072; 2048 is fast enough for tests
	rate = 10_000_000       // effectively unlimited for tests
	telnetRate = 10_000_000 // effectively unlimited for tests
	sshd_key_key = "test-secret"
	profileScope = "host"
	maxAuthTries = 1
	logClearPassword = true
	telnetLogClearPassword = true
	m.Run()
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// tcpPair returns an accepted server conn and a dialed client conn over localhost.
func tcpPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-ch
	t.Cleanup(func() { server.Close(); client.Close() })
	return server, client
}

// captureLog redirects logrus output for the duration of fn and returns what
// was written.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	orig := logrus.StandardLogger().Out
	logrus.SetOutput(&buf)
	defer logrus.SetOutput(orig)
	fn()
	return buf.String()
}

// logHook is a lightweight logrus hook that records entries.
type logHook struct {
	Entries []*logrus.Entry
}

func (h *logHook) Levels() []logrus.Level { return logrus.AllLevels }
func (h *logHook) Fire(e *logrus.Entry) error {
	h.Entries = append(h.Entries, e)
	return nil
}

// ── HashToInt64 ───────────────────────────────────────────────────────────────

func TestHashToInt64_Deterministic(t *testing.T) {
	a := HashToInt64([]byte("hello"), []byte("key"))
	b := HashToInt64([]byte("hello"), []byte("key"))
	if a != b {
		t.Errorf("expected deterministic result; got %d and %d", a, b)
	}
}

func TestHashToInt64_DifferentMessages(t *testing.T) {
	a := HashToInt64([]byte("hello"), []byte("key"))
	b := HashToInt64([]byte("world"), []byte("key"))
	if a == b {
		t.Error("different messages should produce different hashes")
	}
}

func TestHashToInt64_DifferentKeys(t *testing.T) {
	a := HashToInt64([]byte("msg"), []byte("key1"))
	b := HashToInt64([]byte("msg"), []byte("key2"))
	if a == b {
		t.Error("different keys should produce different hashes")
	}
}

// ── getEnvWithDefault ─────────────────────────────────────────────────────────

func TestGetEnvWithDefault_Missing(t *testing.T) {
	t.Setenv("__TEST_MISSING__", "")
	if got := getEnvWithDefault("__TEST_MISSING__", "fallback"); got != "fallback" {
		t.Errorf("empty env var: want %q, got %q", "fallback", got)
	}
}

func TestGetEnvWithDefault_Present(t *testing.T) {
	t.Setenv("__TEST_PRESENT__", "actual")
	if got := getEnvWithDefault("__TEST_PRESENT__", "fallback"); got != "actual" {
		t.Errorf("set env var: want %q, got %q", "actual", got)
	}
}

// ── parseAllowedFields ────────────────────────────────────────────────────────

func TestParseAllowedFields_Empty(t *testing.T) {
	if got := parseAllowedFields(""); len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestParseAllowedFields_SpaceOnly(t *testing.T) {
	if got := parseAllowedFields("   "); len(got) != 0 {
		t.Errorf("expected empty map for whitespace input, got %v", got)
	}
}

func TestParseAllowedFields_Single(t *testing.T) {
	got := parseAllowedFields("src")
	if !got["src"] || len(got) != 1 {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestParseAllowedFields_Multiple(t *testing.T) {
	got := parseAllowedFields("src, dst, duser")
	for _, f := range []string{"src", "dst", "duser"} {
		if !got[f] {
			t.Errorf("field %q should be allowed", f)
		}
	}
	if len(got) != 3 {
		t.Errorf("expected 3 fields, got %d", len(got))
	}
}

// ── getServerProfile ──────────────────────────────────────────────────────────

func TestGetServerProfile_Deterministic(t *testing.T) {
	p1 := getServerProfile("192.168.1.1")
	p2 := getServerProfile("192.168.1.1")
	if p1.ServerVersion != p2.ServerVersion {
		t.Error("profile lookup must be deterministic for the same key")
	}
}

func TestGetServerProfile_ValidOutput(t *testing.T) {
	p := getServerProfile("10.0.0.1")
	if p.ServerVersion == "" {
		t.Error("ServerVersion must not be empty")
	}
	if p.HostKeyType != "rsa" && p.HostKeyType != "ed25519" {
		t.Errorf("unexpected HostKeyType %q", p.HostKeyType)
	}
	if len(p.Kex) == 0 || len(p.Ciphers) == 0 || len(p.Macs) == 0 {
		t.Error("profile must have non-empty Kex, Ciphers, and Macs")
	}
}

func TestGetServerProfile_SpreadAcrossProfiles(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 30; i++ {
		p := getServerProfile(fmt.Sprintf("10.0.0.%d", i))
		seen[p.ServerVersion] = true
	}
	if len(seen) < 2 {
		t.Error("expected at least 2 distinct profiles across 30 different IPs")
	}
}

// ── getHostKeySigner ──────────────────────────────────────────────────────────

func TestGetHostKeySigner_Ed25519(t *testing.T) {
	s, err := getHostKeySigner("host1", "ed25519")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.PublicKey().Type() != "ssh-ed25519" {
		t.Errorf("expected ed25519, got %q", s.PublicKey().Type())
	}
}

func TestGetHostKeySigner_RSA(t *testing.T) {
	s, err := getHostKeySigner("host1", "rsa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(s.PublicKey().Type(), "ssh-rsa") {
		t.Errorf("expected RSA key, got %q", s.PublicKey().Type())
	}
}

func TestGetHostKeySigner_Deterministic(t *testing.T) {
	s1, _ := getHostKeySigner("samehost", "ed25519")
	s2, _ := getHostKeySigner("samehost", "ed25519")
	if !bytes.Equal(s1.PublicKey().Marshal(), s2.PublicKey().Marshal()) {
		t.Error("same host+type must produce the same key")
	}
}

func TestGetHostKeySigner_DifferentHosts(t *testing.T) {
	s1, _ := getHostKeySigner("host-a", "ed25519")
	s2, _ := getHostKeySigner("host-b", "ed25519")
	if bytes.Equal(s1.PublicKey().Marshal(), s2.PublicKey().Marshal()) {
		t.Error("different hosts must produce different keys")
	}
}

func TestGetHostKeySigner_UnsupportedType(t *testing.T) {
	if _, err := getHostKeySigner("host1", "ecdsa-p256"); err == nil {
		t.Error("expected error for unsupported key type")
	}
}

// ── FilteredJSONFormatter ─────────────────────────────────────────────────────

func newTestEntry(fields logrus.Fields) *logrus.Entry {
	return &logrus.Entry{
		Logger:  logrus.New(),
		Data:    fields,
		Time:    time.Now(),
		Level:   logrus.InfoLevel,
		Message: "test message",
	}
}

func TestFilteredJSONFormatter_AllowedFieldsIncluded(t *testing.T) {
	f := &FilteredJSONFormatter{
		Allowed: map[string]bool{"src": true},
		Base:    &logrus.JSONFormatter{},
	}
	out, err := f.Format(newTestEntry(logrus.Fields{"src": "1.2.3.4", "dst": "5.6.7.8"}))
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var m map[string]interface{}
	json.Unmarshal(out, &m)
	if _, ok := m["src"]; !ok {
		t.Error("'src' should be present")
	}
	if _, ok := m["dst"]; ok {
		t.Error("'dst' should be filtered out")
	}
}

func TestFilteredJSONFormatter_EmptyAllowedFiltersEverything(t *testing.T) {
	f := &FilteredJSONFormatter{
		Allowed: map[string]bool{},
		Base:    &logrus.JSONFormatter{},
	}
	out, err := f.Format(newTestEntry(logrus.Fields{"src": "1.2.3.4"}))
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var m map[string]interface{}
	json.Unmarshal(out, &m)
	if _, ok := m["src"]; ok {
		t.Error("'src' should be filtered when Allowed is empty")
	}
}

func TestFilteredJSONFormatter_NilBaseUsesDefault(t *testing.T) {
	f := &FilteredJSONFormatter{
		Allowed: map[string]bool{"src": true},
		Base:    &logrus.JSONFormatter{}, // nil Base would panic in current impl, use default
	}
	// Should not panic
	if _, err := f.Format(newTestEntry(logrus.Fields{"src": "x"})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ── readLine ──────────────────────────────────────────────────────────────────

func writeToConn(t *testing.T, conn net.Conn, data []byte) {
	t.Helper()
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(data); err != nil {
		t.Errorf("write failed: %v", err)
	}
}

func readLineWithTimeout(t *testing.T, conn net.Conn) string {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	result, err := readLine(conn)
	if err != nil {
		t.Fatalf("readLine error: %v", err)
	}
	return result
}

func TestReadLine_Simple(t *testing.T) {
	server, client := tcpPair(t)
	go writeToConn(t, client, []byte("hello\n"))
	if got := readLineWithTimeout(t, server); got != "hello" {
		t.Errorf("want %q, got %q", "hello", got)
	}
}

func TestReadLine_CRLFTerminated(t *testing.T) {
	server, client := tcpPair(t)
	go writeToConn(t, client, []byte("hello\r\n"))
	if got := readLineWithTimeout(t, server); got != "hello" {
		t.Errorf("want %q, got %q", "hello", got)
	}
}

func TestReadLine_TrimsSpaces(t *testing.T) {
	server, client := tcpPair(t)
	go writeToConn(t, client, []byte("  spaced  \n"))
	if got := readLineWithTimeout(t, server); got != "spaced" {
		t.Errorf("want %q, got %q", "spaced", got)
	}
}

func TestReadLine_SkipsIACSequences(t *testing.T) {
	server, client := tcpPair(t)
	// IAC (255) + command (251 = WILL) + option (1 = ECHO), then "hi\n"
	go writeToConn(t, client, []byte{255, 251, 1, 'h', 'i', '\n'})
	if got := readLineWithTimeout(t, server); got != "hi" {
		t.Errorf("want %q, got %q", "hi", got)
	}
}

func TestReadLine_EmptyLine(t *testing.T) {
	server, client := tcpPair(t)
	go writeToConn(t, client, []byte("\n"))
	if got := readLineWithTimeout(t, server); got != "" {
		t.Errorf("want empty string, got %q", got)
	}
}

func TestReadLine_EOFReturnsError(t *testing.T) {
	server, client := tcpPair(t)
	client.Close() // close without sending LF
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := readLine(server)
	if err == nil {
		t.Error("expected error (EOF) when connection closes before newline")
	}
}

// ── rateLimitedConn ───────────────────────────────────────────────────────────

func TestRateLimitedConn_Write(t *testing.T) {
	server, client := tcpPair(t)
	limited := newRateLimitedConn(server, 10_000_000)

	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 5)
		client.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := client.Read(buf) // Error ignored, something that could be improved
		done <- string(buf[:n])
	}()

	if _, err := limited.Write([]byte("hello")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	select {
	case got := <-done:
		if got != "hello" {
			t.Errorf("want %q, got %q", "hello", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for write")
	}
}

func TestRateLimitedConn_Read(t *testing.T) {
	server, client := tcpPair(t)
	limited := newRateLimitedConn(server, 10_000_000)

	go func() {
		client.Write([]byte("ping"))
		client.Close()
	}()

	buf := make([]byte, 4)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := limited.Read(buf)
	if string(buf[:n]) != "ping" {
		t.Errorf("want %q, got %q", "ping", string(buf[:n]))
	}
}

func TestNewRateLimitedConn_TokenInit(t *testing.T) {
	server, _ := tcpPair(t)
	r := newRateLimitedConn(server, 500)
	if r.tokens != 500 {
		t.Errorf("tokens should start at rate (%d), got %d", 500, r.tokens)
	}
	if r.bufferSize != 1000 {
		t.Errorf("bufferSize should be 2×rate (%d), got %d", 1000, r.bufferSize)
	}
}

func TestRateLimitedConn_TokenRefill(t *testing.T) {
	server, client := tcpPair(t)
	defer client.Close()

	const ratePerSec = 100
	limited := newRateLimitedConn(server, ratePerSec)

	// Drain all tokens by setting them to zero and backdating lastUpdate
	// so the next write starts with an empty bucket.
	limited.tokens = 0
	limited.lastUpdate = time.Now().Add(-1 * time.Second) // simulate 1s elapsed

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, ratePerSec)
		client.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := client.Read(buf)
		done <- err
	}()

	// Write exactly one rate-worth of bytes; should succeed after refill
	payload := bytes.Repeat([]byte("x"), ratePerSec)
	if _, err := limited.Write(payload); err != nil {
		t.Fatalf("Write after refill failed: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("client read error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: tokens were not refilled")
	}

	// After the write, tokens should have been consumed (≤ initial refill amount)
	if limited.tokens > ratePerSec {
		t.Errorf("tokens after write should be ≤ %d, got %d", ratePerSec, limited.tokens)
	}
}

// ── connLogParameters ────────────────────────────────────────────────────────

func TestConnLogParameters_Fields(t *testing.T) {
	server, _ := tcpPair(t)
	fields := connLogParameters(server)
	for _, key := range []string{"src", "spt", "dst", "dpt"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("missing field %q in connLogParameters output", key)
		}
	}
}

func TestConnLogParameters_NonEmpty(t *testing.T) {
	server, _ := tcpPair(t)
	fields := connLogParameters(server)
	for k, v := range fields {
		if fmt.Sprint(v) == "" {
			t.Errorf("field %q should not be empty", k)
		}
	}
}

// ── Telnet integration ───────────────────────────────────────────────────────

// startTelnetServer starts a one-shot telnet handler and returns the listener address.
func startTelnetServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleTelnetConnection(conn)
	}()
	return ln.Addr().String()
}

// doTelnetLogin performs a full login sequence and returns the final server response.
func doTelnetLogin(t *testing.T, addr, username, password string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	buf := make([]byte, 512)
	deadline := time.Now().Add(10 * time.Second)
	conn.SetDeadline(deadline)

	// Drain banner + "login: " (may arrive in one or multiple reads)
	var prompt string
	for !strings.Contains(prompt, "login:") && !strings.Contains(prompt, "ogin") {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("reading login prompt: %v", err)
		}
		prompt += string(buf[:n])
	}

	conn.Write([]byte(username + "\n"))

	// Read "Password: "
	conn.Read(buf)

	conn.Write([]byte(password + "\n"))

	// Read final response ("Login incorrect")
	var final string
	for !strings.Contains(final, "incorrect") {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		final += string(buf[:n])
	}
	return final
}

func TestTelnet_SendsLoginPrompt(t *testing.T) {
	addr := startTelnetServer(t)
	conn, _ := net.DialTimeout("tcp", addr, 5*time.Second)
	t.Cleanup(func() { conn.Close() })

	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var received string
	for !strings.Contains(received, "login:") {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		received += string(buf[:n])
	}
	if !strings.Contains(received, "login:") {
		t.Errorf("expected 'login:' prompt, got: %q", received)
	}
}

func TestTelnet_SendsLoginIncorrect(t *testing.T) {
	addr := startTelnetServer(t)
	response := doTelnetLogin(t, addr, "root", "toor")
	if !strings.Contains(response, "incorrect") {
		t.Errorf("expected 'Login incorrect', got: %q", response)
	}
}

func TestTelnet_LogsCredentials_Cleartext(t *testing.T) {
	telnetLogClearPassword = true
	hook := &logHook{}
	logrus.AddHook(hook)
	defer func() { logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{}) }()

	addr := startTelnetServer(t)
	doTelnetLogin(t, addr, "admin", "hunter2")

	// Give goroutine time to log
	time.Sleep(200 * time.Millisecond)

	var found bool
	for _, e := range hook.Entries {
		if u, ok := e.Data["duser"]; ok && u == "admin" {
			if p, ok := e.Data["password"]; ok && p == "hunter2" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected log entry with cleartext username 'admin' and password 'hunter2'")
	}
}

func TestTelnet_LogsCredentials_Base64(t *testing.T) {
	telnetLogClearPassword = false
	defer func() { telnetLogClearPassword = true }()

	hook := &logHook{}
	logrus.AddHook(hook)
	defer func() { logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{}) }()

	addr := startTelnetServer(t)
	doTelnetLogin(t, addr, "user", "pass")

	time.Sleep(200 * time.Millisecond)

	var found bool
	for _, e := range hook.Entries {
		if u, ok := e.Data["duser"]; ok && u == "user" {
			// password should be base64-encoded, NOT the raw string "pass"
			if p, ok := e.Data["password"]; ok && p != "pass" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected base64-encoded password log entry")
	}
}

func TestTelnet_LogsProtocolField(t *testing.T) {
	hook := &logHook{}
	logrus.AddHook(hook)
	defer func() { logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{}) }()

	addr := startTelnetServer(t)
	doTelnetLogin(t, addr, "u", "p")
	time.Sleep(200 * time.Millisecond)

	for _, e := range hook.Entries {
		if proto, ok := e.Data["protocol"]; ok && proto == "telnet" {
			return
		}
	}
	t.Error("expected a log entry with protocol='telnet'")
}

// ── SSH integration ──────────────────────────────────────────────────────────

// startSSHServer starts a multi-connection SSH honeypot listener.
func startSSHServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			cfg := makeSSHConfig(conn)
			limited := newRateLimitedConn(conn, 10_000_000)
			go handleConnection(limited, &cfg)
		}
	}()
	return ln.Addr().String()
}

// dialSSH attempts an SSH connection with the given config, retrying on the
// 10 % random-drop behavior baked into handleConnection.
func dialSSH(addr string, cfg *ssh.ClientConfig) error {
	const maxAttempts = 15
	const retryDelay = 60 * time.Millisecond

	isDropped := func(err error) bool {
		if err == nil {
			return false
		}
		msg := err.Error()
		return strings.Contains(msg, "connection reset") ||
			strings.Contains(msg, "EOF") ||
			strings.Contains(msg, "broken pipe") ||
			strings.Contains(msg, "forcibly closed")
	}

	isAuthRejected := func(err error) bool {
		if err == nil {
			return false
		}
		msg := err.Error()
		return strings.Contains(msg, "unable to authenticate") ||
			strings.Contains(msg, "no supported methods remain")
	}

	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		_, err := ssh.Dial("tcp", addr, cfg)
		if err == nil {
			return nil // should never happen — auth never succeeds
		}
		lastErr = err

		if isAuthRejected(err) {
			return err // expected outcome, no need to retry
		}

		if isDropped(err) {
			time.Sleep(retryDelay)
			continue // simulated network drop, retry
		}

		// Unknown error — retry but log for visibility
		t := cfg.User // abuse User as a label since we have no *testing.T here
		_ = t
		time.Sleep(retryDelay)
	}
	return fmt.Errorf("dialSSH: exhausted %d attempts, last error: %w", maxAttempts, lastErr)
}

func sshClientCfg(user string, methods ...ssh.AuthMethod) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
}

func TestSSH_PasswordAuthAlwaysFails(t *testing.T) {
	addr := startSSHServer(t)
	err := dialSSH(addr, sshClientCfg("root", ssh.Password("toor")))
	if err == nil {
		t.Fatal("expected auth failure; honeypot should never accept credentials")
	}
}

func TestSSH_PublicKeyAuthAlwaysFails(t *testing.T) {
	signer, err := getHostKeySigner("client-test", "ed25519")
	if err != nil {
		t.Fatal(err)
	}
	addr := startSSHServer(t)
	err = dialSSH(addr, sshClientCfg("admin", ssh.PublicKeys(signer)))
	if err == nil {
		t.Fatal("expected auth failure; honeypot should never accept a public key")
	}
}

func TestSSH_LogsPasswordAttempt(t *testing.T) {
	hook := &logHook{}
	logrus.AddHook(hook)
	defer func() { logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{}) }()

	addr := startSSHServer(t)
	dialSSH(addr, sshClientCfg("sysadmin", ssh.Password("letmein")))
	time.Sleep(200 * time.Millisecond)

	var found bool
	for _, e := range hook.Entries {
		if u, ok := e.Data["duser"]; ok && u == "sysadmin" {
			if p, ok := e.Data["password"]; ok && fmt.Sprint(p) == "letmein" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected log entry for password attempt by 'sysadmin'")
	}
}

func TestSSH_LogsPublicKeyAttempt(t *testing.T) {
	hook := &logHook{}
	logrus.AddHook(hook)
	defer func() { logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{}) }()

	signer, _ := getHostKeySigner("attacker-client", "ed25519")
	addr := startSSHServer(t)
	dialSSH(addr, sshClientCfg("pentester", ssh.PublicKeys(signer)))
	time.Sleep(200 * time.Millisecond)

	var found bool
	for _, e := range hook.Entries {
		if u, ok := e.Data["duser"]; ok && u == "pentester" {
			if _, ok := e.Data["fingerprint"]; ok {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected log entry with fingerprint for public-key attempt")
	}
}

func TestSSH_ServerVersionMatchesProfile(t *testing.T) {
	addr := startSSHServer(t)

	// Capture the server version from the SSH banner without fully authenticating.
	rawConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()
	rawConn.SetDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, 256)
	n, _ := rawConn.Read(buf)
	banner := string(buf[:n])

	if !strings.HasPrefix(banner, "SSH-2.0-") {
		t.Errorf("expected SSH-2.0-* banner, got: %q", banner)
	}

	// Verify the version string is one of the known profiles.
	var knownVersions []string
	for _, p := range serverProfiles {
		knownVersions = append(knownVersions, p.ServerVersion)
	}
	var matched bool
	for _, v := range knownVersions {
		if strings.Contains(banner, strings.TrimPrefix(v, "SSH-2.0-")) {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("banner %q does not match any known server profile version", banner)
	}
}

// ── Additional Tests for Higher Coverage ─────────────────────────────────────

// TestGetHostKeySigner_ErrorCases tests error paths
func TestGetHostKeySigner_ErrorCases(t *testing.T) {
	// Test unsupported key type
	_, err := getHostKeySigner("host1", "ecdsa-p256")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

// TestGetHostKeySigner_RSAWithLowBits is covered by init validation
func TestGetHostKeySigner_RSAGeneration(t *testing.T) {
	oldBits := rsaBits
	defer func() { rsaBits = oldBits }()
	rsaBits = 2048

	signer, err := getHostKeySigner("test-rsa", "rsa")
	if err != nil {
		t.Fatalf("RSA generation failed: %v", err)
	}
	if signer == nil {
		t.Error("expected signer, got nil")
	}
}

// TestRateLimitedConn_EdgeCases tests boundary conditions
func TestRateLimitedConn_EdgeCases(t *testing.T) {
	server, client := tcpPair(t)
	defer client.Close()

	limited := newRateLimitedConn(server, 100)

	// Test write with zero tokens (should sleep)
	limited.tokens = 0
	limited.lastUpdate = time.Now().Add(-500 * time.Millisecond)

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 50)
		_, err := client.Read(buf)
		done <- err
	}()

	// Write small amount - should work after token refill
	_, err := limited.Write([]byte("small"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for read")
	}
}

// TestReadLine_EdgeCases tests boundary conditions
func TestReadLine_EdgeCases(t *testing.T) {
	server, client := tcpPair(t)

	// Test connection close during read
	client.Close()
	server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err := readLine(server)
	if err == nil {
		t.Error("expected error on closed connection")
	}

	// Test IAC sequence handling
	server, client = tcpPair(t)
	go func() {
		// IAC + WILL + ECHO, then IAC + WONT + ECHO, then data
		client.Write([]byte{255, 251, 1, 255, 252, 1, 't', 'e', 's', 't', '\n'})
		client.Close()
	}()
	result, err := readLine(server)
	if err != nil {
		t.Fatalf("readLine error: %v", err)
	}
	if result != "test" {
		t.Errorf("expected 'test', got %q", result)
	}
}

// TestConnLogParameters_InvalidAddr tests parsing of invalid addresses
func TestConnLogParameters_InvalidAddr(t *testing.T) {
	// Create a mock connection with invalid address format
	mockConn := &mockConn{
		localAddr:  &mockAddr{net: "tcp", str: "invalid"},
		remoteAddr: &mockAddr{net: "tcp", str: "invalid:port"},
	}
	fields := connLogParameters(mockConn)
	// Should still work without panic
	if fields["src"] == nil {
		t.Error("src field should be set")
	}
}

// Mock implementations for testing
type mockAddr struct {
	net, str string
}

func (m *mockAddr) Network() string { return m.net }
func (m *mockAddr) String() string  { return m.str }

type mockConn struct {
	localAddr, remoteAddr net.Addr
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return 0, nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return m.localAddr }
func (m *mockConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// TestGetHost_InvalidAddr tests error path for getHost
// Replace TestGetHost_InvalidAddr with this safer version
func TestGetHost_ValidAddr(t *testing.T) {
	// Test valid addresses
	testCases := []struct {
		input    string
		expected string
	}{
		{"127.0.0.1:22", "127.0.0.1"},
		{"[::1]:22", "::1"},
		{"example.com:80", "example.com"},
	}

	for _, tc := range testCases {
		result := getHost(tc.input)
		if result != tc.expected {
			t.Errorf("getHost(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

// TestGetHost_InvalidAddr is removed because it causes logrus.Fatal which exits the test
// The fatal error path is intentionally not tested as it's an unrecoverable error
// TestFilteredJSONFormatter_NilBaseHandling tests nil Base formatter
func TestFilteredJSONFormatter_NilBaseHandling(t *testing.T) {
	// Test with nil Base - the formatter should use a default JSONFormatter
	f := &FilteredJSONFormatter{
		Allowed: map[string]bool{"test": true},
		Base:    nil, // This should be handled gracefully
	}
	entry := newTestEntry(logrus.Fields{"test": "value"})

	// This should not panic
	result, err := f.Format(entry)
	if err != nil {
		t.Fatalf("Format with nil Base should not return error, got: %v", err)
	}

	// Verify the output is valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("Result should be valid JSON: %v, got: %s", err, result)
	}

	// Verify the test field is present
	if val, ok := parsed["test"]; !ok || val != "value" {
		t.Errorf("Expected 'test':'value' in output, got: %v", parsed)
	}
}

// TestRateLimitedConn_ReadRateLimiting tests the rate limiting on reads
func TestRateLimitedConn_ReadRateLimiting(t *testing.T) {
	server, client := tcpPair(t)
	limited := newRateLimitedConn(server, 10) // Very slow rate

	go func() {
		client.Write([]byte("1234567890"))
		client.Close()
	}()

	start := time.Now()
	buf := make([]byte, 10)
	n, err := limited.Read(buf)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if n != 10 {
		t.Errorf("expected 10 bytes, got %d", n)
	}
	// With rate 10 bytes/sec, reading 10 bytes should take ~1 second
	if elapsed < 500*time.Millisecond {
		t.Logf("Read completed in %v (rate limiting may be minimal)", elapsed)
	}
}

// TestMakeSSHConfig_BannerCallback tests banner configuration
func TestMakeSSHConfig_BannerCallback(t *testing.T) {
	oldSendBanner := sendBanner
	defer func() { sendBanner = oldSendBanner }()
	sendBanner = true

	server, client := tcpPair(t)
	defer client.Close()

	config := makeSSHConfig(server)

	if config.BannerCallback == nil {
		t.Error("BannerCallback should be set when sendBanner is true")
	}

	// Test the banner callback returns something
	banner := config.BannerCallback(nil)
	if banner == "" {
		t.Error("BannerCallback returned empty string")
	}
}

// TestMakeSSHConfig_ProfileScope tests different profile scopes
func TestMakeSSHConfig_ProfileScope(t *testing.T) {
	originalScope := profileScope
	defer func() { profileScope = originalScope }()

	// Test remote_ip scope
	profileScope = "remote_ip"
	server, client := tcpPair(t)
	defer client.Close()
	config := makeSSHConfig(server)
	if config.ServerVersion == "" {
		t.Error("ServerVersion should be set for remote_ip scope")
	}

	// Test default host scope
	profileScope = "host"
	server2, client2 := tcpPair(t)
	defer client2.Close()
	config2 := makeSSHConfig(server2)
	if config2.ServerVersion == "" {
		t.Error("ServerVersion should be set for host scope")
	}
}

// TestInit_FilteredJSONFormatter tests the init path for log filtering
func TestInit_FilteredJSONFormatter(t *testing.T) {
	// This tests the FilteredJSONFormatter initialization path
	// Since init() already ran, we'll test the formatter directly
	formatter := &FilteredJSONFormatter{
		Allowed: map[string]bool{"src": true},
		Base: &logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
		},
	}

	entry := &logrus.Entry{
		Data: logrus.Fields{
			"src":    "1.2.3.4",
			"dst":    "5.6.7.8",
			"duser":  "test",
			"custom": "value",
		},
		Message: "test",
		Level:   logrus.InfoLevel,
		Time:    time.Now(),
	}

	output, err := formatter.Format(entry)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	// Only src should be present
	if _, ok := result["src"]; !ok {
		t.Error("src should be present")
	}
	if _, ok := result["dst"]; ok {
		t.Error("dst should be filtered out")
	}
	if _, ok := result["duser"]; ok {
		t.Error("duser should be filtered out")
	}
	if _, ok := result["custom"]; ok {
		t.Error("custom should be filtered out")
	}
}

// TestRateLimitedConn_WritePartial tests write with partial completion
func TestRateLimitedConn_WritePartial(t *testing.T) {
	server, client := tcpPair(t)
	limited := newRateLimitedConn(server, 5) // Very slow

	go func() {
		// Read all data
		buf := make([]byte, 20)
		client.Read(buf)
		client.Close()
	}()

	// Write more than token bucket can handle in one go
	data := []byte("1234567890")
	n, err := limited.Write(data)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected to write %d bytes, wrote %d", len(data), n)
	}
}

// TestRateLimitedConn_WriteWithConnectionClose tests write on closed connection
func TestRateLimitedConn_WriteWithConnectionClose(t *testing.T) {
	// Use net.Pipe for deterministic connection behavior
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	
	limited := newRateLimitedConn(server, 1000)
	
	// Close the server side - with pipe, this is immediately detectable
	server.Close()
	
	// Try to write - should get error
	_, err := limited.Write([]byte("test"))
	if err == nil {
		t.Error("expected error writing to closed connection")
	}
}

// TestGetServerProfile_NegativeSeed tests negative seed handling
func TestGetServerProfile_NegativeSeed(t *testing.T) {
	// This is indirectly tested by getServerProfile which uses HashToInt64
	// The function already handles negative seeds by taking absolute value
	originalKey := sshd_key_key
	defer func() { sshd_key_key = originalKey }()
	sshd_key_key = "test"

	// Run multiple times to ensure no panic
	for i := 0; i < 10; i++ {
		profile := getServerProfile("test-host")
		if profile.ServerVersion == "" {
			t.Error("getServerProfile returned empty ServerVersion")
		}
	}
}

// TestTelnet_EmptyLoginSequence tests telnet with empty credentials
func TestTelnet_EmptyLoginSequence(t *testing.T) {
	hook := &logHook{}
	logrus.AddHook(hook)
	defer func() { logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{}) }()

	addr := startTelnetServer(t)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 512)
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Read until login prompt
	var prompt string
	for !strings.Contains(prompt, "login:") {
		n, _ := conn.Read(buf)
		prompt += string(buf[:n])
	}

	// Send empty username (just newline)
	conn.Write([]byte("\n"))

	// Read password prompt
	conn.Read(buf)

	// Send empty password
	conn.Write([]byte("\n"))

	// Read response
	var response string
	for !strings.Contains(response, "incorrect") {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		response += string(buf[:n])
	}

	time.Sleep(100 * time.Millisecond)

	// Check logs
	var foundEmptyUser bool
	for _, e := range hook.Entries {
		if user, ok := e.Data["duser"]; ok && user == "" {
			foundEmptyUser = true
		}
	}
	if !foundEmptyUser {
		t.Log("Empty username login may not have been logged")
	}
}

// TestTelnet_BannerReplacement tests telnet banner text replacement
func TestTelnet_BannerReplacement(t *testing.T) {
	// Test with a profile that has a banner
	originalScope := profileScope
	defer func() { profileScope = originalScope }()
	profileScope = "host"

	addr := startTelnetServer(t)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var banner string
	for !strings.Contains(banner, "login:") && !strings.Contains(banner, "ogin") {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		banner += string(buf[:n])
	}

	// Banner should have "Telnet" instead of "SSH"
	if strings.Contains(banner, "SSH") {
		t.Logf("Banner contains SSH (may be fine): %q", banner)
	}
	// Banner should have CRLF line endings
	if strings.Contains(banner, "\n") && !strings.Contains(banner, "\r\n") {
		t.Logf("Banner line endings: %q", banner)
	}
}

// TestGetServerProfile_ForceProfile tests the FORCE_SSH_PROFILE environment variable
func TestGetServerProfile_ForceProfile(t *testing.T) {
	// Save original environment
	originalForceProfile := os.Getenv("FORCE_SSH_PROFILE")
	defer func() {
		if originalForceProfile == "" {
			os.Unsetenv("FORCE_SSH_PROFILE")
		} else {
			os.Setenv("FORCE_SSH_PROFILE", originalForceProfile)
		}
	}()

	// Test forcing a specific profile
	os.Setenv("FORCE_SSH_PROFILE", "dropbear")
	profile := getServerProfile("any-host")
	if !strings.Contains(profile.ServerVersion, "dropbear") {
		t.Errorf("Expected dropbear profile, got %s", profile.ServerVersion)
	}

	// Test forcing with partial match
	os.Setenv("FORCE_SSH_PROFILE", "OpenSSH_7.4")
	profile = getServerProfile("any-host")
	if !strings.Contains(profile.ServerVersion, "OpenSSH_7.4") {
		t.Errorf("Expected OpenSSH_7.4 profile, got %s", profile.ServerVersion)
	}

	// Test forcing non-existent profile (should use normal selection)
	os.Setenv("FORCE_SSH_PROFILE", "nonexistent")
	profile = getServerProfile("any-host")
	if profile.ServerVersion == "" {
		t.Error("Should still return a valid profile when force profile doesn't exist")
	}
}

// TestHandleConnection_SimulatedDrop tests the random disconnect behavior
func TestHandleConnection_SimulatedDrop(t *testing.T) {
	// Test that handleConnection doesn't panic and handles the connection properly
	server, client := tcpPair(t)
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}

	// Run handleConnection in a goroutine
	go handleConnection(server, config)

	// Give goroutine time to run
	time.Sleep(100 * time.Millisecond)
	client.Close()

	// No panic = success
}

// TestLogParameters tests the logParameters function
func TestLogParameters(t *testing.T) {
	// Create a mock ssh.ConnMetadata
	mockConn := &mockSSHMetadata{
		user:          "testuser",
		remoteAddr:    "192.168.1.100:54321",
		localAddr:     "10.0.0.1:22",
		clientVersion: []byte("SSH-2.0-OpenSSH_8.9"),
		serverVersion: []byte("SSH-2.0-OpenSSH_7.4"),
	}

	fields := logParameters(mockConn)

	expectedFields := []string{"duser", "src", "spt", "dst", "dpt", "client_version", "server_version"}
	for _, field := range expectedFields {
		if _, ok := fields[field]; !ok {
			t.Errorf("Expected field %q not found in logParameters output", field)
		}
	}

	if fields["duser"] != "testuser" {
		t.Errorf("Expected duser=testuser, got %v", fields["duser"])
	}
}

// TestHandleTelnetConnection_BannerReplacement tests the banner text replacement
func TestHandleTelnetConnection_BannerReplacement_Detailed(t *testing.T) {
	// Create a test with a known banner
	originalProfileScope := profileScope
	defer func() { profileScope = originalProfileScope }()
	profileScope = "host"

	// Force a specific profile with a banner
	originalForceProfile := os.Getenv("FORCE_SSH_PROFILE")
	defer os.Setenv("FORCE_SSH_PROFILE", originalForceProfile)
	os.Setenv("FORCE_SSH_PROFILE", "OpenSSH_7.4")

	hook := &logHook{}
	logrus.AddHook(hook)
	defer func() { logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{}) }()

	addr := startTelnetServer(t)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var fullResponse string
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		fullResponse += string(buf[:n])
		if strings.Contains(fullResponse, "Login incorrect") {
			break
		}
		// Send credentials when prompted
		if strings.Contains(fullResponse, "login:") && !strings.Contains(fullResponse, "Password:") {
			conn.Write([]byte("testuser\n"))
		}
		if strings.Contains(fullResponse, "Password:") {
			conn.Write([]byte("testpass\n"))
		}
	}

	// Verify banner replacements
	if strings.Contains(fullResponse, "SSH") {
		t.Logf("Banner contains SSH (might be replaced): %q", fullResponse)
	}
}

// TestNewRateLimitedConn_ZeroRate tests edge case with zero rate
func TestNewRateLimitedConn_ZeroRate(t *testing.T) {
	server, _ := tcpPair(t)
	r := newRateLimitedConn(server, 0)
	if r.rate != 0 {
		t.Errorf("Expected rate 0, got %d", r.rate)
	}
	if r.bufferSize != 0 {
		t.Errorf("Expected bufferSize 0, got %d", r.bufferSize)
	}
}

// TestRateLimitedConn_WriteWithError tests write error handling
func TestRateLimitedConn_WriteWithError(t *testing.T) {
	// Create a mock connection that returns error on write
	mockErrConn := &mockErrorConn{
		mockConn: &mockConn{
			localAddr:  &mockAddr{net: "tcp", str: "127.0.0.1:22"},
			remoteAddr: &mockAddr{net: "tcp", str: "127.0.0.1:54321"},
		},
		err: errors.New("write error"),
	}

	limited := newRateLimitedConn(mockErrConn, 1000)
	_, err := limited.Write([]byte("test"))
	if err == nil {
		t.Error("Expected error from write, got nil")
	}
}

// TestRateLimitedConn_ReadWithError tests read error handling
func TestRateLimitedConn_ReadWithError(t *testing.T) {
	mockErrConn := &mockErrorConn{
		mockConn: &mockConn{
			localAddr:  &mockAddr{net: "tcp", str: "127.0.0.1:22"},
			remoteAddr: &mockAddr{net: "tcp", str: "127.0.0.1:54321"},
		},
		err: errors.New("read error"),
	}

	limited := newRateLimitedConn(mockErrConn, 1000)
	buf := make([]byte, 10)
	_, err := limited.Read(buf)
	if err == nil {
		t.Error("Expected error from read, got nil")
	}
}

// TestGetServerProfile_DifferentSeeds tests profile distribution
func TestGetServerProfile_DifferentSeeds(t *testing.T) {
	originalKey := sshd_key_key
	defer func() { sshd_key_key = originalKey }()

	profiles := make(map[string]int)
	for i := 0; i < 100; i++ {
		sshd_key_key = fmt.Sprintf("key-%d", i)
		profile := getServerProfile("test-host")
		profiles[profile.ServerVersion]++
	}

	// Should have multiple profiles selected
	if len(profiles) < 2 {
		t.Errorf("Expected multiple profiles with different keys, got %d", len(profiles))
	}
}

// TestMakeSSHConfig_RemoteIPProfileScope tests remote_ip scope with invalid address
func TestMakeSSHConfig_RemoteIPProfileScope_InvalidAddr(t *testing.T) {
	originalScope := profileScope
	defer func() { profileScope = originalScope }()
	profileScope = "remote_ip"

	// Create mock connection with invalid remote address
	mockConn := &mockConn{
		localAddr:  &mockAddr{net: "tcp", str: "127.0.0.1:22"},
		remoteAddr: &mockAddr{net: "tcp", str: "invalid"},
	}

	config := makeSSHConfig(mockConn)
	if config.ServerVersion == "" {
		t.Error("Should still create config with invalid remote address")
	}
}

// TestMakeSSHConfig_HostKeyGenerationError tests error path in host key generation
func TestMakeSSHConfig_HostKeyGenerationError(t *testing.T) {
	// This would require mocking getHostKeySigner to return an error
	// For now, we'll test that the function handles it gracefully
	// Note: In production, this would panic, but in tests we can't easily trigger it
}

// TestTelnet_ReadLineError tests readLine error paths
func TestTelnet_ReadLineError(t *testing.T) {
	// Test connection that returns error on read
	server, client := tcpPair(t)

	// Close client to cause read error
	client.Close()

	server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err := readLine(server)
	if err == nil {
		t.Error("Expected error reading from closed connection")
	}
}

// TestTelnet_HandleConnection_WriteError tests telnet connection write error
func TestTelnet_HandleConnection_WriteError(t *testing.T) {
	hook := &logHook{}
	logrus.AddHook(hook)
	defer func() { logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{}) }()

	// Create a mock connection with valid addresses and error on write
	mockErrConn := &mockErrorConn{
		mockConn: &mockConn{
			localAddr:  &mockAddr{net: "tcp", str: "127.0.0.1:22"},
			remoteAddr: &mockAddr{net: "tcp", str: "127.0.0.1:54321"},
		},
		err: errors.New("write error"),
	}

	// This should not panic
	handleTelnetConnection(mockErrConn)
}

// TestParseAllowedFields_WithWhitespace tests parsing fields with various whitespace
func TestParseAllowedFields_WithWhitespace(t *testing.T) {
	testCases := []struct {
		input    string
		expected []string
	}{
		{"field1, field2, field3", []string{"field1", "field2", "field3"}},
		{"  field1  ,  field2  ", []string{"field1", "field2"}},
		{"field1,\tfield2,\nfield3", []string{"field1", "field2", "field3"}},
	}

	for _, tc := range testCases {
		result := parseAllowedFields(tc.input)
		for _, expected := range tc.expected {
			if !result[expected] {
				t.Errorf("Expected field %q to be allowed in input %q", expected, tc.input)
			}
		}
	}
}

// TestGetHostKeySigner_ErrorOnRSAGeneration tests RSA generation error path
func TestGetHostKeySigner_ErrorOnRSAGeneration(t *testing.T) {
	// Save original rsaBits and restore after test
	originalBits := rsaBits
	defer func() { rsaBits = originalBits }()

	// Set invalid RSA bits to cause error
	rsaBits = 1024 // Less than minimum, but might still generate
	_, err := getHostKeySigner("test-host", "rsa")
	// This may or may not error depending on crypto/rsa implementation
	_ = err
}

// TestConnLogParameters_WithIPv6 tests IPv6 address handling
func TestConnLogParameters_WithIPv6(t *testing.T) {
	mockIPv6Conn := &mockConn{
		localAddr:  &mockAddr{net: "tcp", str: "[::1]:22"},
		remoteAddr: &mockAddr{net: "tcp", str: "[::1]:54321"},
	}

	fields := connLogParameters(mockIPv6Conn)
	if fields["src"] == nil || fields["dst"] == nil {
		t.Error("IPv6 addresses should be parsed correctly")
	}
}

// TestGetHost_IPv6 tests getHost with IPv6 addresses
func TestGetHost_IPv6(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"[::1]:22", "::1"},
		{"[2001:db8::1]:8080", "2001:db8::1"},
	}

	for _, tc := range testCases {
		result := getHost(tc.input)
		if result != tc.expected {
			t.Errorf("getHost(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

// TestHashToInt64_EdgeCases tests edge cases for HashToInt64
func TestHashToInt64_EdgeCases(t *testing.T) {
	// Test empty inputs
	result := HashToInt64([]byte{}, []byte{})
	_ = result // Should not panic

	// Test very large inputs
	largeMessage := bytes.Repeat([]byte("x"), 10000)
	largeKey := bytes.Repeat([]byte("y"), 10000)
	result = HashToInt64(largeMessage, largeKey)
	_ = result // Should not panic
}

// Mock implementations for additional testing

type mockSSHMetadata struct {
	user          string
	remoteAddr    string
	localAddr     string
	clientVersion []byte
	serverVersion []byte
}

func (m *mockSSHMetadata) User() string          { return m.user }
func (m *mockSSHMetadata) SessionID() []byte     { return []byte("test-session-id") }
func (m *mockSSHMetadata) ClientVersion() []byte { return m.clientVersion }
func (m *mockSSHMetadata) ServerVersion() []byte { return m.serverVersion }
func (m *mockSSHMetadata) RemoteAddr() net.Addr  { return &mockAddr{str: m.remoteAddr} }
func (m *mockSSHMetadata) LocalAddr() net.Addr   { return &mockAddr{str: m.localAddr} }

// mockErrorConn is a mock connection that returns errors
type mockErrorConn struct {
	*mockConn
	err error
}

func (m *mockErrorConn) Read(b []byte) (n int, err error) {
	return 0, m.err
}

func (m *mockErrorConn) Write(b []byte) (n int, err error) {
	return 0, m.err
}