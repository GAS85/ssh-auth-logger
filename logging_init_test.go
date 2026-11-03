package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// ── init() wiring, run in a subprocess ───────────────────────────────────────
//
// init() has already run in this process, so the real startup path is exercised by re-running the test binary with LOG_TO / LOG_FILE_PATH set. The child logs one line per level and exits.

const logHelperEnv = "SSH_AUTH_LOGGER_LOG_HELPER"

const (
	startupMarker = "Starting SSH Auth Logger"
	runtimeMarker = "runtime-marker" // logged as info
	warnMarker    = "warn-marker"
	errorMarker   = "error-marker"
)

func TestLogToHelperProcess(t *testing.T) {
	if os.Getenv(logHelperEnv) != "1" {
		t.Skip("only used as a subprocess by the TestInit_LogTo tests")
	}
	logger.Info(runtimeMarker)
	logger.Warn(warnMarker)
	logger.Error(errorMarker)
}

// helperOutput is what the child process wrote to its two console streams.
type helperOutput struct{ stdout, stderr string }

// runInitHelper runs the helper with the given extra environment and returns what it wrote to stdout and stderr and how it exited.
func runInitHelper(t *testing.T, env ...string) (out helperOutput, err error) {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=^TestLogToHelperProcess$", "-test.count=1")
	// Later entries win, so the explicit resets below shield the child from the caller's environment.
	cmd.Env = append(os.Environ(), logHelperEnv+"=1", "LOG_TO=", "LOG_FILE_PATH=")
	cmd.Env = append(cmd.Env, env...)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return helperOutput{stdout: outBuf.String(), stderr: errBuf.String()}, err
}

// startupEntry finds the startup line in the log output and decodes it.
func startupEntry(t *testing.T, output string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, startupMarker) {
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatalf("startup line is not JSON: %v\n%s", err, line)
			}
			return m
		}
	}
	t.Fatalf("no startup line in output:\n%s", output)
	return nil
}

// expect checks that every want is in text and no notWant is.
func expect(t *testing.T, name, text string, want, notWant []string) {
	t.Helper()
	for _, m := range want {
		if !strings.Contains(text, m) {
			t.Errorf("%s should contain %q:\n%s", name, m, text)
		}
	}
	for _, m := range notWant {
		if strings.Contains(text, m) {
			t.Errorf("%s must not contain %q:\n%s", name, m, text)
		}
	}
}

// Info and debug lines (including the startup message) go to stdout, warnings and errors to stderr.
func TestInit_LogToConsole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")

	out, err := runInitHelper(t, "LOG_TO=console", "LOG_FILE_PATH="+path)
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out.stderr)
	}
	expect(t, "stdout", out.stdout, []string{startupMarker, runtimeMarker}, []string{warnMarker, errorMarker})
	expect(t, "stderr", out.stderr, []string{warnMarker, errorMarker}, []string{startupMarker, runtimeMarker})

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("no file may be created for LOG_TO=console (stat err: %v)", err)
	}
}

func TestInit_DefaultIsConsole(t *testing.T) {
	out, err := runInitHelper(t)
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out.stderr)
	}
	expect(t, "stdout", out.stdout, []string{startupMarker, runtimeMarker}, []string{warnMarker})
	expect(t, "stderr", out.stderr, []string{warnMarker}, []string{startupMarker, runtimeMarker})

	if got := startupEntry(t, out.stdout)["logging"].(map[string]any)["LOG_TO"]; got != "console" {
		t.Errorf("startup LOG_TO = %v, want console", got)
	}
}

func TestInit_LogToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")

	out, err := runInitHelper(t, "LOG_TO=file", "LOG_FILE_PATH="+path)
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out.stderr)
	}

	// Console: only the startup message with all settings (stdout, it is an info line). Nothing of the runtime output, whatever its level.
	expect(t, "stdout", out.stdout, []string{startupMarker}, []string{runtimeMarker, warnMarker, errorMarker})
	expect(t, "stderr", out.stderr, nil, []string{startupMarker, runtimeMarker, warnMarker, errorMarker})

	// File: startup message and every runtime line.
	content := readTestFile(t, path)
	if strings.Count(content, startupMarker) != 1 {
		t.Errorf("file must have the startup message exactly once:\n%s", content)
	}
	expect(t, "file", content, []string{runtimeMarker, warnMarker, errorMarker}, nil)

	// Both copies of the startup message carry all settings, including the new ones.
	for name, text := range map[string]string{"console": out.stdout, "file": content} {
		entry := startupEntry(t, text)
		logging, _ := entry["logging"].(map[string]any)
		if logging["LOG_TO"] != "file" || logging["LOG_FILE_PATH"] != path {
			t.Errorf("%s: logging settings = %v", name, logging)
		}
		if ssh, _ := entry["ssh"].(map[string]any); ssh["SSHD_BIND"] == nil {
			t.Errorf("%s: startup message lacks the SSH settings: %v", name, entry)
		}
		if telnet, _ := entry["telnet"].(map[string]any); telnet["TELNET_BIND"] == nil {
			t.Errorf("%s: startup message lacks the Telnet settings: %v", name, entry)
		}
	}
}

func TestInit_LogToBoth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")

	out, err := runInitHelper(t, "LOG_TO=both", "LOG_FILE_PATH="+path)
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out.stderr)
	}
	content := readTestFile(t, path)

	// Each line appears once per destination, on the stream of its level.
	expect(t, "stdout", out.stdout, []string{startupMarker, runtimeMarker}, []string{warnMarker, errorMarker})
	expect(t, "stderr", out.stderr, []string{warnMarker, errorMarker}, []string{startupMarker, runtimeMarker})
	expect(t, "file", content, []string{startupMarker, runtimeMarker, warnMarker, errorMarker}, nil)

	for name, text := range map[string]string{"stdout": out.stdout, "file": content} {
		if n := strings.Count(text, startupMarker); n != 1 {
			t.Errorf("%s: startup message appears %d times, want exactly once", name, n)
		}
	}
	for name, text := range map[string]string{"stderr": out.stderr, "file": content} {
		if n := strings.Count(text, warnMarker); n != 1 {
			t.Errorf("%s: warning appears %d times, want exactly once", name, n)
		}
	}
}

func TestInit_LogToFile_AppendsToExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, []byte("from an earlier run\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if out, err := runInitHelper(t, "LOG_TO=file", "LOG_FILE_PATH="+path); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out.stderr)
	}

	content := readTestFile(t, path)
	if !strings.HasPrefix(content, "from an earlier run\n") || !strings.Contains(content, runtimeMarker) {
		t.Errorf("existing content must be kept and new lines appended:\n%s", content)
	}
}

// A fatal configuration error after the output is set up must be visible on the console (stderr), even though LOG_TO=file would send runtime output to the file only.
func TestInit_FatalErrorIsShownOnConsoleAndInFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")

	out, err := runInitHelper(t, "LOG_TO=file", "LOG_FILE_PATH="+path, "SSHD_RATE=not-a-number")
	if err == nil {
		t.Fatal("expected the helper to exit with an error")
	}
	if !strings.Contains(out.stderr, "Invalid SSHD_RATE") {
		t.Errorf("stderr must show the fatal error:\n%s", out.stderr)
	}
	if strings.Contains(out.stdout, "Invalid SSHD_RATE") {
		t.Errorf("a fatal error must not go to stdout:\n%s", out.stdout)
	}
	if !strings.Contains(readTestFile(t, path), "Invalid SSHD_RATE") {
		t.Error("file should have the fatal error as well")
	}
}

func TestInit_InvalidConfigurationIsFatal(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name      string
		env       []string
		wantInErr string
	}{
		{"unknown mode", []string{"LOG_TO=syslog"}, "invalid LOG_TO"},
		{"file without path", []string{"LOG_TO=file"}, "LOG_FILE_PATH"},
		{"both without path", []string{"LOG_TO=both"}, "LOG_FILE_PATH"},
		{"unopenable path", []string{"LOG_TO=file", "LOG_FILE_PATH=" + filepath.Join(dir, "missing", "app.log")}, "LOG_FILE_PATH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runInitHelper(t, tc.env...)
			if err == nil {
				t.Fatalf("expected a non-zero exit, output:\n%s\n%s", out.stdout, out.stderr)
			}
			if !strings.Contains(out.stderr, tc.wantInErr) {
				t.Errorf("stderr should mention %q:\n%s", tc.wantInErr, out.stderr)
			}
			if strings.Contains(out.stdout+out.stderr, startupMarker) {
				t.Error("must not start up with an invalid log configuration")
			}
		})
	}
}
