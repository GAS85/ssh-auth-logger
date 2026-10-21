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
// init() has already run in this process, so the real startup path is exercised by re-running the test binary with LOG_TO / LOG_FILE_PATH set. The child logs one runtime line and exits.

const logHelperEnv = "SSH_AUTH_LOGGER_LOG_HELPER"

const (
	startupMarker = "Starting SSH Auth Logger"
	runtimeMarker = "runtime-marker"
)

func TestLogToHelperProcess(t *testing.T) {
	if os.Getenv(logHelperEnv) != "1" {
		t.Skip("only used as a subprocess by the TestInit_LogTo tests")
	}
	logger.Info(runtimeMarker)
}

// runInitHelper runs the helper with the given extra environment and returns what it wrote to the console (stderr) and how it exited.
func runInitHelper(t *testing.T, env ...string) (stderr string, err error) {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=^TestLogToHelperProcess$", "-test.count=1")
	// Later entries win, so the explicit resets below shield the child from the caller's environment.
	cmd.Env = append(os.Environ(), logHelperEnv+"=1", "LOG_TO=", "LOG_FILE_PATH=")
	cmd.Env = append(cmd.Env, env...)

	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return errBuf.String(), err
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

func TestInit_LogToConsole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")

	stderr, err := runInitHelper(t, "LOG_TO=console", "LOG_FILE_PATH="+path)
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, startupMarker) || !strings.Contains(stderr, runtimeMarker) {
		t.Errorf("console must have startup and runtime output:\n%s", stderr)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("no file may be created for LOG_TO=console (stat err: %v)", err)
	}
}

func TestInit_DefaultIsConsole(t *testing.T) {
	stderr, err := runInitHelper(t)
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, startupMarker) || !strings.Contains(stderr, runtimeMarker) {
		t.Errorf("console must have startup and runtime output:\n%s", stderr)
	}
	if got := startupEntry(t, stderr)["logging"].(map[string]any)["LOG_TO"]; got != "console" {
		t.Errorf("startup LOG_TO = %v, want console", got)
	}
}

func TestInit_LogToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")

	stderr, err := runInitHelper(t, "LOG_TO=file", "LOG_FILE_PATH="+path)
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, stderr)
	}

	// Console: the startup message with all settings, but not the runtime line.
	if !strings.Contains(stderr, startupMarker) {
		t.Errorf("startup message must be shown on the console even with LOG_TO=file:\n%s", stderr)
	}
	if strings.Contains(stderr, runtimeMarker) {
		t.Errorf("runtime output must not reach the console with LOG_TO=file:\n%s", stderr)
	}

	// File: startup message and runtime line.
	content := readTestFile(t, path)
	if strings.Count(content, startupMarker) != 1 || !strings.Contains(content, runtimeMarker) {
		t.Errorf("file must have the startup message once and the runtime line:\n%s", content)
	}

	// Both copies of the startup message carry all settings, including the new ones.
	for name, text := range map[string]string{"console": stderr, "file": content} {
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

	stderr, err := runInitHelper(t, "LOG_TO=both", "LOG_FILE_PATH="+path)
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, stderr)
	}
	content := readTestFile(t, path)

	for name, text := range map[string]string{"console": stderr, "file": content} {
		if n := strings.Count(text, startupMarker); n != 1 {
			t.Errorf("%s: startup message appears %d times, want exactly once", name, n)
		}
		if !strings.Contains(text, runtimeMarker) {
			t.Errorf("%s: runtime line missing", name)
		}
	}
}

func TestInit_LogToFile_AppendsToExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, []byte("from an earlier run\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if stderr, err := runInitHelper(t, "LOG_TO=file", "LOG_FILE_PATH="+path); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, stderr)
	}

	content := readTestFile(t, path)
	if !strings.HasPrefix(content, "from an earlier run\n") || !strings.Contains(content, runtimeMarker) {
		t.Errorf("existing content must be kept and new lines appended:\n%s", content)
	}
}

// A fatal configuration error after the output is set up must be visible on the console, even though LOG_TO=file would send it to the file only.
func TestInit_FatalErrorIsShownOnConsoleAndInFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")

	stderr, err := runInitHelper(t, "LOG_TO=file", "LOG_FILE_PATH="+path, "SSHD_RATE=not-a-number")
	if err == nil {
		t.Fatal("expected the helper to exit with an error")
	}
	if !strings.Contains(stderr, "Invalid SSHD_RATE") {
		t.Errorf("console must show the fatal error:\n%s", stderr)
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
			stderr, err := runInitHelper(t, tc.env...)
			if err == nil {
				t.Fatalf("expected a non-zero exit, output:\n%s", stderr)
			}
			if !strings.Contains(stderr, tc.wantInErr) {
				t.Errorf("console should mention %q:\n%s", tc.wantInErr, stderr)
			}
			if strings.Contains(stderr, startupMarker) {
				t.Error("must not start up with an invalid log configuration")
			}
		})
	}
}
