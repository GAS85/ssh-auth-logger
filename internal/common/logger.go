package common

import "github.com/sirupsen/logrus"

// NewLogger returns the logger entry used for connection events: the standard logrus logger with the fields every honeypot log line carries. product is the application name.
func NewLogger(product string) *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		"destinationServicename": "sshd",
		"product":                product,
	})
}
