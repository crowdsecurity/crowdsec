package vlclient

import (
	"time"
)

// Log represents a VictoriaLogs log line
// See: https://docs.victoriametrics.com/victorialogs/querying/#querying-logs
type Log struct {
	Message string
	Time    time.Time
	// Used to store the value to set the type label
	Program string
}
