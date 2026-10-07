package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Log destinations selectable with LOG_TO.
const (
	logToConsole = "console"
	logToFile    = "file"
	logToBoth    = "both"
)

// parseLogTo normalises the LOG_TO value. An empty value means "console".
func parseLogTo(value string) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(value)); v {
	case "", logToConsole:
		return logToConsole, nil
	case logToFile, logToBoth:
		return v, nil
	default:
		return "", fmt.Errorf("invalid LOG_TO %q (allowed: %s, %s, %s)", value, logToConsole, logToFile, logToBoth)
	}
}

// logOutputs holds the writers logrus is pointed at over the process lifetime.
type logOutputs struct {
	// Mode is the normalised LOG_TO value: console, file or both.
	Mode string
	// Startup receives everything logged while the application initialises, including the startup message with all settings. It always includes the console, and in addition the file if a file was requested, so the configuration is visible on the console even with LOG_TO=file.
	Startup io.Writer
	// Runtime receives all later log lines, as selected by LOG_TO.
	Runtime io.Writer
	// File is the log file writer, nil if LOG_TO=console.
	File *reopenFileWriter
}

// setupLogOutput builds the writers for the given LOG_TO / LOG_FILE_PATH values. console is where "console" output goes (os.Stderr in production, as logrus does by default).
func setupLogOutput(logTo, filePath string, console io.Writer) (*logOutputs, error) {
	mode, err := parseLogTo(logTo)
	if err != nil {
		return nil, err
	}

	if mode == logToConsole {
		return &logOutputs{Mode: mode, Startup: console, Runtime: console}, nil
	}

	if strings.TrimSpace(filePath) == "" {
		return nil, fmt.Errorf("LOG_TO=%s requires LOG_FILE_PATH to be set", mode)
	}

	file, err := newReopenFileWriter(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot open LOG_FILE_PATH: %w", err)
	}

	both := multiWriter{console, file}
	if mode == logToBoth {
		return &logOutputs{Mode: mode, Startup: both, Runtime: both, File: file}, nil
	}

	// mode == file: console only gets the startup output.
	return &logOutputs{Mode: mode, Startup: both, Runtime: file, File: file}, nil
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
