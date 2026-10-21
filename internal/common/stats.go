package common

import (
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/GAS85/ssh-auth-logger/internal/abuse"
	"github.com/sirupsen/logrus"
)

// Stats holds the run counters. All fields are safe for concurrent use.
type Stats struct {
	Started time.Time

	SSHConnections    atomic.Uint64
	TelnetConnections atomic.Uint64
	// DroppedConnections counts SSH connections closed on purpose by the simulated network issue.
	DroppedConnections atomic.Uint64
	SSHPasswords       atomic.Uint64
	TelnetPasswords    atomic.Uint64
	SSHKeys            atomic.Uint64

	// Currently open connections (gauges): incremented when a handler starts, decremented when it returns.
	OpenSSH    atomic.Int64
	OpenTelnet atomic.Int64
}

// NewStats returns zeroed counters that start counting uptime now.
func NewStats() *Stats { return &Stats{Started: time.Now()} }

// Snapshot is a point-in-time copy of all statistics. It is what the REST endpoint returns and what is logged on shutdown.
type Snapshot struct {
	Product                string            `json:"product"`
	StartedAt              string            `json:"startedAt"`
	Uptime                 string            `json:"uptime"`
	UptimeSeconds          int64             `json:"uptimeSeconds"`
	Connections            uint64            `json:"connections"`
	SSHConnections         uint64            `json:"sshConnections"`
	TelnetConnections      uint64            `json:"telnetConnections"`
	DroppedConnections     uint64            `json:"droppedConnections"`
	OpenConnections        int64             `json:"openConnections"`
	OpenSSHConnections     int64             `json:"openSshConnections"`
	OpenTelnetConnections  int64             `json:"openTelnetConnections"`
	PasswordAttempts       uint64            `json:"passwordAttempts"`
	SSHPasswordAttempts    uint64            `json:"sshPasswordAttempts"`
	TelnetPasswordAttempts uint64            `json:"telnetPasswordAttempts"`
	SSHKeyAttempts         uint64            `json:"sshKeyAttempts"`
	ReportsTriggered       uint64            `json:"reportsTriggered"`
	ReportsSent            uint64            `json:"reportsSent"`
	ReportsByBackend       map[string]uint64 `json:"reportsByBackend"`
}

// Snapshot reads all counters at time now. mgr may be nil.
// The values are read one after another, not under a common lock, so a snapshot taken while connections arrive can be off by a few counts between fields; each field is exact.
func (s *Stats) Snapshot(product string, mgr *abuse.Manager, now time.Time) Snapshot {
	ssh, telnet := s.SSHConnections.Load(), s.TelnetConnections.Load()
	sshPw, telnetPw := s.SSHPasswords.Load(), s.TelnetPasswords.Load()
	openSSH, openTelnet := s.OpenSSH.Load(), s.OpenTelnet.Load()
	uptime := now.Sub(s.Started)
	rep := mgr.Stats()

	return Snapshot{
		Product:                product,
		StartedAt:              s.Started.UTC().Format(time.RFC3339),
		Uptime:                 uptime.Round(time.Second).String(),
		UptimeSeconds:          int64(uptime.Seconds()),
		Connections:            ssh + telnet,
		SSHConnections:         ssh,
		TelnetConnections:      telnet,
		DroppedConnections:     s.DroppedConnections.Load(),
		OpenConnections:        openSSH + openTelnet,
		OpenSSHConnections:     openSSH,
		OpenTelnetConnections:  openTelnet,
		PasswordAttempts:       sshPw + telnetPw,
		SSHPasswordAttempts:    sshPw,
		TelnetPasswordAttempts: telnetPw,
		SSHKeyAttempts:         s.SSHKeys.Load(),
		ReportsTriggered:       rep.ReportsTriggered,
		ReportsSent:            rep.ReportsSent,
		ReportsByBackend:       rep.SentByBackend,
	}
}

// LogShutdownStats writes one "Shutting down" line with the run statistics to w.
// It uses its own logger with a plain JSON formatter, so the LOG_FILTER setting cannot strip the statistics, the same way the startup message is not filtered.
func LogShutdownStats(w io.Writer, product string, s *Stats, mgr *abuse.Manager, sig string, now time.Time) {
	l := logrus.New()
	l.SetOutput(w)
	l.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339Nano})

	// Same field names as the REST endpoint: go through JSON instead of listing them twice.
	fields := logrus.Fields{}
	if raw, err := json.Marshal(s.Snapshot(product, mgr, now)); err == nil {
		_ = json.Unmarshal(raw, &fields)
	}
	fields["signal"] = sig
	l.WithFields(fields).Info("Shutting down, run statistics")
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
