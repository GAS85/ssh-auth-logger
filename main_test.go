package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
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
		n, _ := client.Read(buf)
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
// 10 % random-drop behaviour baked into handleConnection.
func dialSSH(addr string, cfg *ssh.ClientConfig) error {
	var lastErr error
	for i := 0; i < 8; i++ {
		_, err := ssh.Dial("tcp", addr, cfg)
		if err == nil {
			return nil // should not happen — auth never succeeds
		}
		lastErr = err
		// Distinguish "auth rejected" (expected) from "connection reset" (random drop).
		if strings.Contains(err.Error(), "unable to authenticate") ||
			strings.Contains(err.Error(), "ssh: handshake failed") {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return lastErr
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