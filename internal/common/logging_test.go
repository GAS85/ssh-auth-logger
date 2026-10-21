package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func newTestLogWriter(t *testing.T, path string) *reopenFileWriter {
	t.Helper()
	w, err := newReopenFileWriter(path)
	if err != nil {
		t.Fatalf("newReopenFileWriter: %v", err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}

func mustWrite(t *testing.T, w interface{ Write([]byte) (int, error) }, s string) {
	t.Helper()
	n, err := w.Write([]byte(s))
	if err != nil || n != len(s) {
		t.Fatalf("Write(%q) = %d, %v", s, n, err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("console is gone") }

// ── ParseLogTo ───────────────────────────────────────────────────────────────

func TestParseLogTo(t *testing.T) {
	valid := map[string]string{
		"":          "console",
		"console":   "console",
		"CONSOLE":   "console",
		"  file  ":  "file",
		"File":      "file",
		"both":      "both",
		"BOTH":      "both",
		"\tboth\n":  "both",
		"  Console": "console",
	}
	for in, want := range valid {
		got, err := ParseLogTo(in)
		if err != nil || got != want {
			t.Errorf("ParseLogTo(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	for _, in := range []string{"stdout", "files", "console,file", "file,console", "none", "1"} {
		if got, err := ParseLogTo(in); err == nil {
			t.Errorf("ParseLogTo(%q) = %q, want error", in, got)
		}
	}
}

// ── reopenFileWriter ─────────────────────────────────────────────────────────

func TestReopenFileWriter_CreatesFileAndAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")

	w1 := newTestLogWriter(t, path)
	mustWrite(t, w1, "one\n")
	w1.Close()

	// A restart must keep what is already there.
	w2 := newTestLogWriter(t, path)
	mustWrite(t, w2, "two\n")

	if got := readTestFile(t, path); got != "one\ntwo\n" {
		t.Errorf("file = %q, want %q", got, "one\ntwo\n")
	}
}

func TestReopenFileWriter_NotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	path := filepath.Join(t.TempDir(), "app.log")
	newTestLogWriter(t, path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The log can contain clear-text credentials.
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		t.Errorf("log file mode %o must not grant access to others", perm)
	}
}

func TestReopenFileWriter_MissingDirectoryFails(t *testing.T) {
	if _, err := newReopenFileWriter(filepath.Join(t.TempDir(), "no-such-dir", "app.log")); err == nil {
		t.Error("expected an error for a path in a missing directory")
	}
}

// logrotate in its default mode renames the file; the writer must continue in a new file at the original path.
func TestReopenFileWriter_FollowsRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	w := newTestLogWriter(t, path)

	mustWrite(t, w, "before\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, "after\n")

	if got := readTestFile(t, path+".1"); got != "before\n" {
		t.Errorf("rotated file = %q, want only the old line", got)
	}
	if got := readTestFile(t, path); got != "after\n" {
		t.Errorf("new file = %q, want only the new line", got)
	}
}

// logrotate's "create" option puts a fresh file at the original path right after the rename, so the path never looks missing. The writer has to notice that it is a different file.
func TestReopenFileWriter_FollowsReplacedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	w := newTestLogWriter(t, path)

	mustWrite(t, w, "before\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, "after\n")

	if got := readTestFile(t, path+".1"); got != "before\n" {
		t.Errorf("rotated file = %q, want only the old line", got)
	}
	if got := readTestFile(t, path); got != "after\n" {
		t.Errorf("new file = %q, want only the new line", got)
	}
}

func TestReopenFileWriter_FollowsRepeatedRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	w := newTestLogWriter(t, path)

	for i := 1; i <= 3; i++ {
		mustWrite(t, w, fmt.Sprintf("line-%d\n", i))
		if err := os.Rename(path, fmt.Sprintf("%s.%d", path, i)); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, w, "line-4\n")

	for i := 1; i <= 3; i++ {
		if got, want := readTestFile(t, fmt.Sprintf("%s.%d", path, i)), fmt.Sprintf("line-%d\n", i); got != want {
			t.Errorf("%s.%d = %q, want %q", path, i, got, want)
		}
	}
	if got := readTestFile(t, path); got != "line-4\n" {
		t.Errorf("current file = %q", got)
	}
}

func TestReopenFileWriter_RecreatesRemovedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	w := newTestLogWriter(t, path)

	mustWrite(t, w, "before\n")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, "after\n")

	if got := readTestFile(t, path); got != "after\n" {
		t.Errorf("recreated file = %q, want %q", got, "after\n")
	}
}

// logrotate's copytruncate keeps the inode and empties the file.
func TestReopenFileWriter_SurvivesCopyTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	w := newTestLogWriter(t, path)

	mustWrite(t, w, "before\n")
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, "after\n")

	if got := readTestFile(t, path); got != "after\n" {
		t.Errorf("file = %q, want %q (no leading NUL bytes from a stale offset)", got, "after\n")
	}
}

// If the path cannot be reopened, lines must not be dropped: they go to the old (rotated) file.
func TestReopenFileWriter_KeepsOldHandleWhenReopenFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("renaming an open file")
	}
	path := filepath.Join(t.TempDir(), "app.log")
	w := newTestLogWriter(t, path)

	mustWrite(t, w, "before\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	// A directory now sits at the log path: stat works, but it cannot be opened for writing.
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, "still logged\n")

	if got := readTestFile(t, path+".1"); got != "before\nstill logged\n" {
		t.Errorf("rotated file = %q", got)
	}

	// Once the path is usable again, writing moves over to it.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, "recovered\n")
	if got := readTestFile(t, path); got != "recovered\n" {
		t.Errorf("new file = %q, want %q", got, "recovered\n")
	}
}

func TestReopenFileWriter_WriteAfterCloseFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	w := newTestLogWriter(t, path)

	mustWrite(t, w, "kept\n")
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close should be a no-op, got %v", err)
	}
	if _, err := w.Write([]byte("lost\n")); err == nil {
		t.Error("Write after Close must fail")
	}
	if got := readTestFile(t, path); got != "kept\n" {
		t.Errorf("file = %q", got)
	}
}

// Many writers and a rotation in the middle: every line must end up in exactly one of the two files. Run with -race.
func TestReopenFileWriter_ConcurrentWritesAcrossRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	w := newTestLogWriter(t, path)

	const writers, perWriter = 8, 100

	half := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				if _, err := w.Write([]byte(fmt.Sprintf("w%d-%d\n", g, i))); err != nil {
					t.Errorf("write: %v", err)
					return
				}
				if g == 0 && i == perWriter/2 {
					once.Do(func() { close(half) })
				}
			}
		}(g)
	}

	<-half
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	seen := map[string]int{}
	for _, p := range []string{path + ".1", path} {
		for _, line := range strings.Split(strings.TrimSuffix(readTestFile(t, p), "\n"), "\n") {
			if line != "" {
				seen[line]++
			}
		}
	}
	if len(seen) != writers*perWriter {
		t.Errorf("got %d distinct lines, want %d", len(seen), writers*perWriter)
	}
	for line, n := range seen {
		if n != 1 {
			t.Errorf("line %q written %d times", line, n)
		}
	}
	if strings.TrimSpace(readTestFile(t, path)) == "" {
		t.Error("nothing was written to the new file after rotation")
	}
}

// ── multiWriter ──────────────────────────────────────────────────────────────

func TestMultiWriter_WritesToAll(t *testing.T) {
	var a, b bytes.Buffer
	n, err := multiWriter{&a, &b}.Write([]byte("hi"))
	if err != nil || n != 2 || a.String() != "hi" || b.String() != "hi" {
		t.Errorf("n=%d err=%v a=%q b=%q", n, err, a.String(), b.String())
	}
}

func TestMultiWriter_FailingWriterDoesNotBlockOthers(t *testing.T) {
	var after bytes.Buffer
	if _, err := (multiWriter{failingWriter{}, &after}).Write([]byte("hi")); err == nil {
		t.Error("expected the error to be reported")
	}
	if after.String() != "hi" {
		t.Errorf("writer after the failing one got %q, want %q", after.String(), "hi")
	}
}

// ── SetupLogOutput ───────────────────────────────────────────────────────────

func TestSetupLogOutput_Console(t *testing.T) {
	var console bytes.Buffer
	path := filepath.Join(t.TempDir(), "app.log")

	// A LOG_FILE_PATH is ignored (and not created) in console mode.
	out, err := SetupLogOutput("console", path, &console)
	if err != nil {
		t.Fatal(err)
	}
	if out.Mode != "console" || out.File != nil {
		t.Errorf("mode=%q file=%v", out.Mode, out.File)
	}

	mustWrite(t, out.Startup, "start\n")
	mustWrite(t, out.Runtime, "run\n")
	if console.String() != "start\nrun\n" {
		t.Errorf("console = %q", console.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("log file must not be created in console mode (stat err: %v)", err)
	}
}

func TestSetupLogOutput_EmptyMeansConsole(t *testing.T) {
	var console bytes.Buffer
	out, err := SetupLogOutput("", "", &console)
	if err != nil || out.Mode != "console" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

// With LOG_TO=file the startup output must still reach the console, and the file as well; everything afterwards goes to the file only.
func TestSetupLogOutput_FileMode(t *testing.T) {
	var console bytes.Buffer
	path := filepath.Join(t.TempDir(), "app.log")

	out, err := SetupLogOutput("file", path, &console)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.File.Close() })

	mustWrite(t, out.Startup, "start\n")
	mustWrite(t, out.Runtime, "run\n")

	if console.String() != "start\n" {
		t.Errorf("console = %q, want only the startup output", console.String())
	}
	if got := readTestFile(t, path); got != "start\nrun\n" {
		t.Errorf("file = %q, want startup and runtime output", got)
	}
}

func TestSetupLogOutput_BothMode(t *testing.T) {
	var console bytes.Buffer
	path := filepath.Join(t.TempDir(), "app.log")

	out, err := SetupLogOutput("BOTH", path, &console)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.File.Close() })

	mustWrite(t, out.Startup, "start\n")
	mustWrite(t, out.Runtime, "run\n")

	// The startup line appears once per destination, not twice on the console.
	if console.String() != "start\nrun\n" {
		t.Errorf("console = %q", console.String())
	}
	if got := readTestFile(t, path); got != "start\nrun\n" {
		t.Errorf("file = %q", got)
	}
}

func TestSetupLogOutput_FileModeFollowsRotation(t *testing.T) {
	var console bytes.Buffer
	path := filepath.Join(t.TempDir(), "app.log")

	out, err := SetupLogOutput("file", path, &console)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.File.Close() })

	mustWrite(t, out.Runtime, "before\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, out.Runtime, "after\n")

	if got := readTestFile(t, path); got != "after\n" {
		t.Errorf("file = %q", got)
	}
}

func TestSetupLogOutput_Errors(t *testing.T) {
	var console bytes.Buffer
	dir := t.TempDir()

	cases := []struct {
		name, logTo, path, wantInErr string
	}{
		{"invalid mode", "syslog", filepath.Join(dir, "a.log"), "LOG_TO"},
		{"file without path", "file", "", "LOG_FILE_PATH"},
		{"both without path", "both", "   ", "LOG_FILE_PATH"},
		{"unwritable path", "file", filepath.Join(dir, "missing", "a.log"), "LOG_FILE_PATH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := SetupLogOutput(tc.logTo, tc.path, &console)
			if err == nil {
				t.Fatalf("expected an error, got %+v", out)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("error %q should mention %q", err, tc.wantInErr)
			}
		})
	}
}

func TestSetupLogOutput_BrokenConsoleDoesNotStopFileLogging(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")

	out, err := SetupLogOutput("both", path, failingWriter{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.File.Close() })

	out.Runtime.Write([]byte("still here\n"))
	if got := readTestFile(t, path); got != "still here\n" {
		t.Errorf("file = %q", got)
	}
}

// A logrus logger writing through the runtime writer keeps working across a rotation, and every line is valid JSON.
func TestSetupLogOutput_WithLogrusAcrossRotation(t *testing.T) {
	var console bytes.Buffer
	path := filepath.Join(t.TempDir(), "app.log")

	out, err := SetupLogOutput("file", path, &console)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.File.Close() })

	l := logrus.New()
	l.SetFormatter(&logrus.JSONFormatter{})
	l.SetOutput(out.Runtime)

	l.WithField("src", "192.0.2.1").Info("before rotation")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	l.WithField("src", "192.0.2.2").Info("after rotation")

	for p, want := range map[string]string{path + ".1": "before rotation", path: "after rotation"} {
		var m map[string]any
		if err := json.Unmarshal([]byte(readTestFile(t, p)), &m); err != nil {
			t.Fatalf("%s is not a single JSON line: %v", p, err)
		}
		if m["msg"] != want {
			t.Errorf("%s: msg = %v, want %q", p, m["msg"], want)
		}
	}
	if console.Len() != 0 {
		t.Errorf("nothing may reach the console in file mode, got %q", console.String())
	}
}
