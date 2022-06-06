package loki

import "time"

type Entry struct {
	Timestamp time.Time
	Line      string
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
