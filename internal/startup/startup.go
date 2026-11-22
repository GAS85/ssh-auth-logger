package startup

import (
	"os"

	"github.com/sirupsen/logrus"
)

// GetEnvWithDefault returns the environment value for key,
// returning fallback instead if it is missing or blank.
func GetEnvWithDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

// ShowAll reports whether the startup output should list every setting, defaults included.
// That is the case when the log level is debug (LOG_LEVEL=debug or trace).
func ShowAll() bool { return logrus.IsLevelEnabled(logrus.DebugLevel) }

// AddIfNotDefault adds a field to the startup output only when its value differs from the default,
// or always when the log level is debug (see ShowAll). The level must already be set when this is called.
//
// It is generic so that value and defaultValue must have the same type: comparing, say,
// an int with a string would otherwise never be equal and the field would always be shown.
func AddIfNotDefault[T comparable](fields logrus.Fields, key string, value, defaultValue T) {
	if value != defaultValue || ShowAll() {
		fields[key] = value
	}
}
