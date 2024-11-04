package vlclient

import (
	"time"
)

// Log represents a VictoriaLogs log line
// See: https://docs.victoriametrics.com/victorialogs/querying/#querying-logs
type Log struct {
	Message string    `json:"_msg"`
	Time    time.Time `json:"_time"`
}
