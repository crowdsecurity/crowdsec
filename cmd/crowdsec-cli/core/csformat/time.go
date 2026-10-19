// Package csformat formats values for human-readable CLI output.
package csformat

import "time"

func LocalTime(value time.Time) time.Time {
	return value.Local() //nolint:gosmopolitan // Human-readable output follows the process timezone.
}

func LocalTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}

	return new(LocalTime(*value))
}

func LocalTimestamp(value string) string {
	timestamp, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}

	return LocalTime(timestamp).Format(time.RFC3339Nano)
}
