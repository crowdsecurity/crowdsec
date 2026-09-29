package pipeline

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCopyForBucketIndependence(t *testing.T) {
	src := Event{
		Meta:        map[string]string{"source_ip": "1.2.3.4", "log_type": "http_access-log"},
		Parsed:      map[string]string{"verb": "GET"},
		Enriched:    map[string]string{"IsoCode": "FR"},
		Unmarshaled: map[string]any{"json": map[string]any{"a": 1}},
	}

	cp := src.CopyForBucket()

	// same content right after the copy
	require.Equal(t, src.Meta, cp.Meta)
	require.Equal(t, src.Parsed, cp.Parsed)
	require.Equal(t, src.Enriched, cp.Enriched)
	require.Equal(t, src.Unmarshaled, cp.Unmarshaled)

	// mutating the copy must not affect the source (this is the #4459 guarantee)
	cp.SetMeta("injected", "1")
	cp.SetParsed("verb", "POST")

	require.NotContains(t, src.Meta, "injected", "writing copy.Meta leaked into source")
	require.Equal(t, "GET", src.Parsed["verb"], "writing copy.Parsed leaked into source")
}

func TestCopyForBucketNilMapsStayNil(t *testing.T) {
	var src Event

	cp := src.CopyForBucket()

	// maps.Clone preserves nil, which the downstream nil checks rely on
	require.Nil(t, cp.Meta)
	require.Nil(t, cp.Parsed)
}

// BenchmarkCopyForBucket isolates the per-pour cost of the #4459 fix: cloning
// the writable maps of a realistic parsed HTTP event.
func BenchmarkCopyForBucket(b *testing.B) {
	src := Event{
		Meta: map[string]string{
			"source_ip": "1.2.3.4", "service": "http", "log_type": "http_access-log",
			"http_status": "404", "http_path": "/wp-admin/", "http_verb": "GET",
			"http_user_agent": "curl/8.0", "http_host": "example.com", "machine": "test",
			"datasource_path": "/var/log/traefik/access.log", "datasource_type": "file",
		},
		Parsed:   map[string]string{"verb": "GET", "status": "404", "request": "/wp-admin/"},
		Enriched: map[string]string{"IsoCode": "FR", "ASNumber": "1234", "ASNOrg": "Example"},
	}

	for b.Loop() {
		_ = src.CopyForBucket()
	}
}
