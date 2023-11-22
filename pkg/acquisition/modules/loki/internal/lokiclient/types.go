package lokiclient

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
	e.Timestamp = time.Unix(0, int64(t))
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

type LokiResponse struct {
	Streams        []Stream      `json:"streams"`
	DroppedEntries []interface{} `json:"dropped_entries"` //We don't care about the actual content i think ?
}

// LokiQuery GET response.
// See https://grafana.com/docs/loki/latest/api/#get-lokiapiv1query
type LokiQueryRangeResponse struct {
	Status string `json:"status"`
	Data   Data   `json:"data"`
}

type Data struct {
	ResultType string      `json:"resultType"`
	Result     []Stream    `json:"result"` // Warning, just stream value is handled
	Stats      interface{} `json:"stats"`  // Stats is boring, just ignore it
}
