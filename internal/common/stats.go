package common

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

// Stats holds the counters reported when the application is stopped. All fields are safe for concurrent use.
type Stats struct {
	Started time.Time

	SSHConnections    atomic.Uint64
	TelnetConnections atomic.Uint64
	SSHPasswords      atomic.Uint64
	TelnetPasswords   atomic.Uint64
	SSHKeys           atomic.Uint64
}

// NewStats returns zeroed counters that start counting uptime now.
func NewStats() *Stats { return &Stats{Started: time.Now()} }

// LogShutdownStats writes one "Shutting down" line with the run statistics to w.
// It uses its own logger with a plain JSON formatter, so the LOG_FILTER setting cannot strip the statistics, the same way the startup message is not filtered.
func LogShutdownStats(w io.Writer, product string, s *Stats, mgr *abuse.Manager, sig string, now time.Time) {
	l := logrus.New()
	l.SetOutput(w)
	l.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339Nano})

	ssh, telnet := s.SSHConnections.Load(), s.TelnetConnections.Load()
	sshPw, telnetPw := s.SSHPasswords.Load(), s.TelnetPasswords.Load()
	uptime := now.Sub(s.Started)

	rep := mgr.Stats()
	byBackend := make(map[string]any, len(rep.SentByBackend))
	for k, v := range rep.SentByBackend {
		byBackend[k] = v
	}

	l.WithFields(logrus.Fields{
		"product":                product,
		"signal":                 sig,
		"uptime":                 uptime.Round(time.Second).String(),
		"uptimeSeconds":          int64(uptime.Seconds()),
		"connections":            ssh + telnet,
		"sshConnections":         ssh,
		"telnetConnections":      telnet,
		"passwordAttempts":       sshPw + telnetPw,
		"sshPasswordAttempts":    sshPw,
		"telnetPasswordAttempts": telnetPw,
		"sshKeyAttempts":         s.SSHKeys.Load(),
		"reportsTriggered":       rep.ReportsTriggered,
		"reportsSent":            rep.ReportsSent,
		"reportsByBackend":       byBackend,
	}).Info("Shutting down, run statistics")
}

// NotifyShutdown registers for SIGTERM and SIGINT. It is separate from HandleShutdown so the registration is already in place when the handler goroutine starts.
func NotifyShutdown() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	return ch
}

// HandleShutdown blocks until a signal arrives on sigs, logs the statistics to w and then calls exit(0).
func HandleShutdown(sigs <-chan os.Signal, w io.Writer, product string, s *Stats, mgr *abuse.Manager, exit func(int)) {
	sig := <-sigs
	LogShutdownStats(w, product, s, mgr, sig.String(), time.Now())
	exit(0)
}
