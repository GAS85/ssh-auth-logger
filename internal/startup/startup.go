package startup

import (
	"github.com/sirupsen/logrus"
	"os"
)

// GetEnvWithDefault returns the environment value for key
// returning fallback instead if it is missing or blank
func GetEnvWithDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

// addEnvIfNotDefault adds a field only when the environment variable
// is explicitly set to a non-default value.
func AddIfNotDefault(fields logrus.Fields, key string, value, defaultValue interface{}) {
	if value != defaultValue {
		fields[key] = value
	}
}
