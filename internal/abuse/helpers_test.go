package abuse

import (
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// testHook is a logrus hook that records entries (safe for concurrent use).
type testHook struct {
	mu      sync.Mutex
	entries []*logrus.Entry
}

func (h *testHook) Levels() []logrus.Level { return logrus.AllLevels }

func (h *testHook) Fire(e *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, e)
	return nil
}

// find returns the first entry whose message contains substr, or nil.
func (h *testHook) find(substr string) *logrus.Entry {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range h.entries {
		if strings.Contains(e.Message, substr) {
			return e
		}
	}
	return nil
}

// waitFor polls until an entry containing substr appears.
func (h *testHook) waitFor(t *testing.T, substr string) *logrus.Entry {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e := h.find(substr); e != nil {
			return e
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no log entry containing %q", substr)
	return nil
}

func (h *testHook) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.entries)
}

// isolate snapshots every package-level setting that Setup or the tests may change and restores them when the test ends.
func isolate(t *testing.T) {
	t.Helper()
	oldLogger, oldGetenv, oldUA := logger, getenv, userAgent
	oa, ori, oci, ose := abuseAttempts, abuseReportInterval, abuseCleanupInterval, abuseStateExpiry
	t.Cleanup(func() {
		logger, getenv, userAgent = oldLogger, oldGetenv, oldUA
		abuseAttempts, abuseReportInterval, abuseCleanupInterval, abuseStateExpiry = oa, ori, oci, ose
	})
}

// captureLogs swaps the package logger for one that records into the returned hook.
func captureLogs(t *testing.T) *testHook {
	t.Helper()
	isolate(t)
	l := logrus.New()
	l.SetOutput(io.Discard)
	l.SetLevel(logrus.DebugLevel)
	h := &testHook{}
	l.AddHook(h)
	logger = logrus.NewEntry(l)
	return h
}

// env builds a Getenv function from key, value pairs; unset keys yield the default.
func env(kv ...string) func(string, string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(name, def string) string {
		if v, ok := m[name]; ok && v != "" {
			return v
		}
		return def
	}
}

// useEnv installs an environment for the package (as Setup would).
func useEnv(t *testing.T, kv ...string) {
	t.Helper()
	isolate(t)
	getenv = env(kv...)
}

type fatalExit struct{}

// expectFatal runs fn, which must call logrus.Fatal. The process exit is turned into a panic that is recovered here, and the fatal message is returned.
func expectFatal(t *testing.T, fn func()) string {
	t.Helper()

	std := logrus.StandardLogger()
	oldExit, oldOut := std.ExitFunc, std.Out
	h := &testHook{}
	oldHooks := std.ReplaceHooks(make(logrus.LevelHooks))
	std.AddHook(h)
	std.SetOutput(io.Discard)
	std.ExitFunc = func(int) { panic(fatalExit{}) }
	defer func() {
		std.ExitFunc = oldExit
		std.SetOutput(oldOut)
		std.ReplaceHooks(oldHooks)
	}()

	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected logrus.Fatal to be called")
			}
			if _, ok := r.(fatalExit); !ok {
				panic(r)
			}
		}()
		fn()
	}()

	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.entries) == 0 {
		t.Fatal("fatal exit without a log message")
	}
	return h.entries[len(h.entries)-1].Message
}