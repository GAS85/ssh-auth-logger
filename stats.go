package main

import (
	"io"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/GAS85/ssh-auth-logger/internal/abuse"
	"github.com/sirupsen/logrus"
)

// appStats holds the counters reported when the application is stopped. All fields are safe for concurrent use.
type appStats struct {
	started time.Time

	sshConnections    atomic.Uint64
	telnetConnections atomic.Uint64
	sshPasswords      atomic.Uint64
	telnetPasswords   atomic.Uint64
	sshKeys           atomic.Uint64
}

// stats is updated by the SSH and Telnet handlers.
var stats = &appStats{started: time.Now()}

// logShutdownStats writes one "Shutting down" line with the run statistics to w.
// It uses its own logger with a plain JSON formatter, so the LOG_FILTER setting cannot strip the statistics, the same way the startup message is not filtered.
func logShutdownStats(w io.Writer, s *appStats, mgr *abuse.Manager, sig string, now time.Time) {
	l := logrus.New()
	l.SetOutput(w)
	l.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339Nano})

	ssh, telnet := s.sshConnections.Load(), s.telnetConnections.Load()
	sshPw, telnetPw := s.sshPasswords.Load(), s.telnetPasswords.Load()
	uptime := now.Sub(s.started)

	rep := mgr.Stats()
	byBackend := make(map[string]any, len(rep.SentByBackend))
	for k, v := range rep.SentByBackend {
		byBackend[k] = v
	}

	l.WithFields(logrus.Fields{
		"product":                appName,
		"signal":                 sig,
		"uptime":                 uptime.Round(time.Second).String(),
		"uptimeSeconds":          int64(uptime.Seconds()),
		"connections":            ssh + telnet,
		"sshConnections":         ssh,
		"telnetConnections":      telnet,
		"passwordAttempts":       sshPw + telnetPw,
		"sshPasswordAttempts":    sshPw,
		"telnetPasswordAttempts": telnetPw,
		"sshKeyAttempts":         s.sshKeys.Load(),
		"reportsTriggered":       rep.ReportsTriggered,
		"reportsSent":            rep.ReportsSent,
		"reportsByBackend":       byBackend,
	}).Info("Shutting down, run statistics")
}

// notifyShutdown registers for SIGTERM and SIGINT. It is separate from handleShutdown so the registration is already in place when the handler goroutine starts.
func notifyShutdown() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	return ch
}

// handleShutdown blocks until a signal arrives on sigs, logs the statistics to w and then calls exit(0).
func handleShutdown(sigs <-chan os.Signal, w io.Writer, s *appStats, mgr *abuse.Manager, exit func(int)) {
	sig := <-sigs
	logShutdownStats(w, s, mgr, sig.String(), time.Now())
	exit(0)
}
