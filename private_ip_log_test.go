package main

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// setPrivateAsUsual sets LOG_PRIVATE_IPS_AS_USUAL for one test.
func setPrivateAsUsual(t *testing.T, v bool) {
	t.Helper()
	old := logPrivateIPsAsUsual
	logPrivateIPsAsUsual = v
	t.Cleanup(func() { logPrivateIPsAsUsual = old })
}

// levelOf returns the level of the first entry with the given message, or false.
func levelOf(h *logHook, msg string) (logrus.Level, bool) {
	for _, e := range h.Entries {
		if e.Message == msg {
			return e.Level, true
		}
	}
	return 0, false
}

func TestLogLevels_ByIP(t *testing.T) {
	cases := []struct {
		src         string
		asUsual     bool
		conn, login logrus.Level
	}{
		{"10.1.2.3", false, logrus.WarnLevel, logrus.ErrorLevel},
		{"192.168.0.7", false, logrus.WarnLevel, logrus.ErrorLevel},
		{"172.16.5.5", false, logrus.WarnLevel, logrus.ErrorLevel},
		{"127.0.0.1", false, logrus.WarnLevel, logrus.ErrorLevel},
		{"fd12::1", false, logrus.WarnLevel, logrus.ErrorLevel},
		{"203.0.113.9", false, logrus.InfoLevel, logrus.InfoLevel},
		{"2001:db8::1", false, logrus.InfoLevel, logrus.InfoLevel},
		{"", false, logrus.InfoLevel, logrus.InfoLevel},
		// LOG_PRIVATE_IPS_AS_USUAL=true restores the old behaviour
		{"10.1.2.3", true, logrus.InfoLevel, logrus.InfoLevel},
		{"127.0.0.1", true, logrus.InfoLevel, logrus.InfoLevel},
	}
	for _, tc := range cases {
		setPrivateAsUsual(t, tc.asUsual)
		if got := connLogLevel(tc.src); got != tc.conn {
			t.Errorf("connLogLevel(%q, asUsual=%v) = %v, want %v", tc.src, tc.asUsual, got, tc.conn)
		}
		if got := attemptLogLevel(tc.src); got != tc.login {
			t.Errorf("attemptLogLevel(%q, asUsual=%v) = %v, want %v", tc.src, tc.asUsual, got, tc.login)
		}
	}
}

func TestPrivateIP_TelnetLevels(t *testing.T) {
	for _, asUsual := range []bool{false, true} {
		setPrivateAsUsual(t, asUsual)
		hook := &logHook{}
		logrus.AddHook(hook)

		addr := startTelnetServer(t) // clients connect from 127.0.0.1
		doTelnetLogin(t, addr, "admin", "pw")
		time.Sleep(100 * time.Millisecond)
		logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{})

		wantConn, wantLogin := logrus.WarnLevel, logrus.ErrorLevel
		if asUsual {
			wantConn, wantLogin = logrus.InfoLevel, logrus.InfoLevel
		}
		if lvl, ok := levelOf(hook, "Telnet connection"); !ok || lvl != wantConn {
			t.Errorf("asUsual=%v: Telnet connection level = %v (found=%v), want %v", asUsual, lvl, ok, wantConn)
		}
		if lvl, ok := levelOf(hook, "Telnet login attempt"); !ok || lvl != wantLogin {
			t.Errorf("asUsual=%v: Telnet login attempt level = %v (found=%v), want %v", asUsual, lvl, ok, wantLogin)
		}
	}
}

func TestPrivateIP_SSHLevels(t *testing.T) {
	for _, asUsual := range []bool{false, true} {
		setPrivateAsUsual(t, asUsual)
		hook := &logHook{}
		logrus.AddHook(hook)

		signer, err := getHostKeySigner("private-ip-client", "ed25519")
		if err != nil {
			t.Fatal(err)
		}
		addr := startSSHServer(t)
		dialSSH(addr, sshClientCfg("root", ssh.Password("toor")))
		dialSSH(addr, sshClientCfg("root", ssh.PublicKeys(signer)))
		time.Sleep(200 * time.Millisecond)
		logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{})

		wantConn, wantLogin := logrus.WarnLevel, logrus.ErrorLevel
		if asUsual {
			wantConn, wantLogin = logrus.InfoLevel, logrus.InfoLevel
		}
		for msg, want := range map[string]logrus.Level{
			"SSH connection":        wantConn,
			"Request with password": wantLogin,
			"Request with key":      wantLogin,
		} {
			if lvl, ok := levelOf(hook, msg); !ok || lvl != want {
				t.Errorf("asUsual=%v: %q level = %v (found=%v), want %v", asUsual, msg, lvl, ok, want)
			}
		}
	}
}
