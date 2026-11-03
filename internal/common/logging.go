package common

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
)

// Log destinations selectable with LOG_TO.
const (
	LogToConsole = "console"
	logToFile    = "file"
	logToBoth    = "both"
)

// ParseLogTo normalises the LOG_TO value. An empty value means "console".
func ParseLogTo(value string) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(value)); v {
	case "", LogToConsole:
		return LogToConsole, nil
	case logToFile, logToBoth:
		return v, nil
	default:
		return "", fmt.Errorf("invalid LOG_TO %q (allowed: %s, %s, %s)", value, LogToConsole, logToFile, logToBoth)
	}
}

// Log lines are split by level: info and debug (the normal operation: connections, login attempts, startup message, statistics) go to one writer, warnings and everything worse to another. On the console these are stdout and stderr.
var (
	severeLevels = []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel, logrus.WarnLevel}
	normalLevels = []logrus.Level{logrus.InfoLevel, logrus.DebugLevel, logrus.TraceLevel}
)

// LogOutputs holds the writers logrus is pointed at over the process lifetime. Each phase has two: the plain one receives info and debug lines, the *Err one warnings and above.
type LogOutputs struct {
	// Mode is the normalised LOG_TO value: console, file or both.
	Mode string
	// Startup and StartupErr receive everything logged while the application initialises, including the startup message with all settings. They always include the console, and in addition the file if a file was requested, so the configuration is visible on the console even with LOG_TO=file. The startup message itself is an info line, so it is written to Startup.
	Startup    io.Writer
	StartupErr io.Writer
	// Runtime and RuntimeErr receive all later log lines, as selected by LOG_TO.
	Runtime    io.Writer
	RuntimeErr io.Writer
	// File is the log file writer, nil if LOG_TO=console.
	File *reopenFileWriter
}

// SetupLogOutput builds the writers for the given LOG_TO / LOG_FILE_PATH values. stdout and stderr are where "console" output goes (os.Stdout and os.Stderr in production): info and debug lines to stdout, warnings and above to stderr. A log file gets both kinds.
func SetupLogOutput(logTo, filePath string, stdout, stderr io.Writer) (*LogOutputs, error) {
	mode, err := ParseLogTo(logTo)
	if err != nil {
		return nil, err
	}

	if mode == LogToConsole {
		return &LogOutputs{Mode: mode, Startup: stdout, StartupErr: stderr, Runtime: stdout, RuntimeErr: stderr}, nil
	}

	if strings.TrimSpace(filePath) == "" {
		return nil, fmt.Errorf("LOG_TO=%s requires LOG_FILE_PATH to be set", mode)
	}

	file, err := newReopenFileWriter(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot open LOG_FILE_PATH: %w", err)
	}

	bothOut, bothErr := multiWriter{stdout, file}, multiWriter{stderr, file}
	if mode == logToBoth {
		return &LogOutputs{Mode: mode, Startup: bothOut, StartupErr: bothErr, Runtime: bothOut, RuntimeErr: bothErr, File: file}, nil
	}

	// mode == file: console only gets the startup output.
	return &LogOutputs{Mode: mode, Startup: bothOut, StartupErr: bothErr, Runtime: file, RuntimeErr: file, File: file}, nil
}

// UseStartup points l at the startup writers: output of level info and below to Startup, warnings and above to StartupErr.
func (o *LogOutputs) UseStartup(l *logrus.Logger) { routeByLevel(l, o.Startup, o.StartupErr) }

// UseRuntime points l at the runtime writers, as selected by LOG_TO. It replaces the routing set up by UseStartup.
func (o *LogOutputs) UseRuntime(l *logrus.Logger) { routeByLevel(l, o.Runtime, o.RuntimeErr) }

// routeByLevel sends info/debug/trace entries of l to normal and warn/error/fatal/panic entries to severe. It uses logrus writer hooks, so the logger's own output is switched off: every entry is delivered by exactly one hook. Any other hook of l is removed.
func routeByLevel(l *logrus.Logger, normal, severe io.Writer) {
	l.SetOutput(io.Discard)
	l.ReplaceHooks(make(logrus.LevelHooks))
	l.AddHook(&writer.Hook{Writer: severe, LogLevels: severeLevels})
	l.AddHook(&writer.Hook{Writer: normal, LogLevels: normalLevels})
}

// multiWriter writes to every writer, even if an earlier one fails (unlike io.MultiWriter). A broken console must not stop file logging and vice versa. It returns the first error seen.
type multiWriter []io.Writer

func (m multiWriter) Write(p []byte) (int, error) {
	var firstErr error
	for _, w := range m {
		if _, err := w.Write(p); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return 0, firstErr
	}
	return len(p), nil
}

// reopenFileWriter appends to a log file and follows the path, not the file handle: if the file is renamed (logrotate), removed, or replaced, the next write opens the path again and carries on in the new file. Truncation (logrotate copytruncate) works as well, because the file is opened with O_APPEND.
//
// The path is checked on every write. Log volume of a honeypot is low, and this way no line lands in a rotated file.
type reopenFileWriter struct {
	mu     sync.Mutex
	path   string
	f      *os.File
	info   os.FileInfo // identity of f at the time it was opened
	closed bool
}

// File permissions
const logFileMode = 0o640

func newReopenFileWriter(path string) (*reopenFileWriter, error) {
	w := &reopenFileWriter{path: path}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

// open (re)opens the path and replaces the current handle. Caller holds mu (or has exclusive access).
func (w *reopenFileWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, logFileMode)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	if w.f != nil {
		w.f.Close()
	}
	w.f, w.info = f, info
	return nil
}

// rotated reports whether the path no longer refers to the open file.
func (w *reopenFileWriter) rotated() bool {
	cur, err := os.Stat(w.path)
	if err != nil {
		// Typically "does not exist" between rotation and re-creation.
		return true
	}
	return !os.SameFile(cur, w.info)
}

// Write implements io.Writer.
func (w *reopenFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, os.ErrClosed
	}

	// If the path cannot be reopened (directory gone, permissions), keep writing to the old handle: the lines end up in the rotated file instead of being lost.
	if w.rotated() {
		_ = w.open()
	}

	n, err := w.f.Write(p)
	if err != nil && n == 0 {
		// The handle went bad. Reopen once and retry; a partial write is not retried, as that would duplicate its beginning.
		if rerr := w.open(); rerr == nil {
			return w.f.Write(p)
		}
	}
	return n, err
}

// Close closes the file. Later writes fail instead of silently recreating it.
func (w *reopenFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true
	return w.f.Close()
}
