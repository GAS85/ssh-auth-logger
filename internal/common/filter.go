package common

import (
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// ParseAllowedFields parses a comma-separated list of allowed fields
func ParseAllowedFields(env string) map[string]bool {
	fields := make(map[string]bool)
	for _, f := range strings.Split(env, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			fields[f] = true
		}
	}
	return fields
}

type FilteredJSONFormatter struct {
	Allowed map[string]bool
	Base    *logrus.JSONFormatter
}

// Format filters the log entry to include only allowed fields
func (f *FilteredJSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// Ensure Base is not nil
	var baseFormatter *logrus.JSONFormatter
	if f.Base == nil {
		// Create a default JSON formatter with sensible defaults
		baseFormatter = &logrus.JSONFormatter{
			TimestampFormat:  time.RFC3339Nano,
			DisableTimestamp: false,
			PrettyPrint:      false,
		}
	} else {
		baseFormatter = f.Base
	}

	// Filter the fields
	filtered := logrus.Fields{}
	for k, v := range entry.Data {
		if len(f.Allowed) == 0 {
			// If Allowed is empty, don't include any custom fields
			continue
		}
		if f.Allowed[k] {
			filtered[k] = v
		}
	}

	// Create a new entry with filtered data
	newEntry := *entry
	newEntry.Data = filtered

	// Format using the base formatter
	return baseFormatter.Format(&newEntry)
}
