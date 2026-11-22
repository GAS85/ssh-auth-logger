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

// AddIfNotDefault adds a field to the startup output only when its value differs from the default.
//
// It is generic so that value and defaultValue must have the same type: comparing, say,
// an int with a string would otherwise never be equal and the field would always be shown.
func AddIfNotDefault[T comparable](fields logrus.Fields, key string, value, defaultValue T) {
	if value != defaultValue {
		fields[key] = value
	}
}
