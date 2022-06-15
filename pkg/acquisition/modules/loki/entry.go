package loki

import (
	"encoding/json"
	"strconv"
	"time"
)

type Entry struct {
	Timestamp time.Time
	Line      string
}

func (e *Entry) UnmarshalJSON(b []byte) error {
	var values []string
	err := json.Unmarshal(b, &values)
	if err != nil {
		return err
	}
	t, err := strconv.Atoi(values[0])
	if err != nil {
		return err
	}
	e.Timestamp = time.Unix(int64(t), 0)
	e.Line = values[1]
	return nil
}

type Stream struct {
	Stream  map[string]string `json:"stream"`
	Entries []Entry           `json:"values"`
}

type DroppedEntry struct {
	Labels    map[string]string `json:"labels"`
	Timestamp time.Time         `json:"timestamp"`
}

type Tail struct {
	Streams        []Stream       `json:"streams"`
	DroppedEntries []DroppedEntry `json:"dropped_entries"`
}

// LokiQuery GET response.
// See https://grafana.com/docs/loki/latest/api/#get-lokiapiv1query
type LokiQuery struct {
	Status string `json:"status"`
	Data   Data   `json:"data"`
}

type Data struct {
	ResultType string         `json:"resultType"`
	Result     []StreamResult `json:"result"` // Warning, just stream value is handled
	Stats      interface{}    `json:"stats"`  // Stats is boring, just ignore it
}

type StreamResult struct {
	Stream map[string]string `json:"stream"`
	Values []Entry           `json:"values"`
}
