package appsec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
)

// Per-output-path mutexes so concurrent requests appending to the same
// labeled JSONL file can't interleave half-lines, while distinct labels
// never contend with each other. The outer mutex only guards the map
// itself; the per-path mutex guards the actual write.
var (
	fpDumpMapMu sync.Mutex
	fpDumpLocks = map[string]*sync.Mutex{}
)

func fpDumpLockFor(path string) *sync.Mutex {
	fpDumpMapMu.Lock()
	defer fpDumpMapMu.Unlock()
	m, ok := fpDumpLocks[path]
	if !ok {
		m = &sync.Mutex{}
		fpDumpLocks[path] = m
	}
	return m
}

var fpLabelSanitizer = regexp.MustCompile(`[^a-z0-9]+`)

// sanitizeFpLabel returns a filesystem-safe slug for the supplied label:
// lowercase, runs of non-alphanumerics collapsed to a single underscore,
// leading/trailing underscores trimmed, capped at 40 chars. An empty or
// all-junk label collapses to "unlabeled".
//
// Two labels that differ only in non-alphanumeric content (e.g. "bot-1"
// and "bot_1") will share the same file; the original label is always
// preserved verbatim inside every JSON line so disambiguation downstream
// is still possible.
func sanitizeFpLabel(label string) string {
	s := fpLabelSanitizer.ReplaceAllString(strings.ToLower(label), "_")
	s = strings.Trim(s, "_")
	if s == "" {
		return "unlabeled"
	}
	if len(s) > 40 {
		s = strings.Trim(s[:40], "_")
		if s == "" {
			return "unlabeled"
		}
	}
	return s
}

// fpDumpEntry is the on-disk record shape: one of these per line in the
// labeled JSONL file. Field order is fixed by the struct so downstream
// consumers can rely on the JSON layout.
type fpDumpEntry struct {
	Label       string                     `json:"label"`
	Timestamp   time.Time                  `json:"timestamp"`
	RemoteAddr  string                     `json:"remote_addr,omitempty"`
	UserAgent   string                     `json:"user_agent,omitempty"`
	Host        string                     `json:"host,omitempty"`
	URI         string                     `json:"uri,omitempty"`
	Method      string                     `json:"method,omitempty"`
	Fingerprint *challenge.FingerprintData `json:"fingerprint"`
}

// DumpFingerprint appends one compact JSON object (JSONL) describing the
// supplied human label, a server-side UTC timestamp, a minimal request
// context block (remote addr, UA, host, URI, method), and the full
// FingerprintData to <tmpdir>/crowdsec_fp_dump_<sanitized-label>.jsonl.
//
// Re-calling with the same label appends to the same file; different
// labels produce different files. Designed for offline dataset collection
// from on_challenge_submit and post_eval hooks.
//
// Returns the written path, or "" on error (always logged via logrus).
// A nil fingerprint is treated as a soft no-op (warning logged) so a
// rule firing in a hook before the fingerprint is populated doesn't
// crash request processing.
func DumpFingerprint(label string, fp *challenge.FingerprintData, req *ParsedRequest) string {
	if fp == nil {
		log.Warnf("DumpFingerprint(%q) called with nil fingerprint, skipping", label)
		return ""
	}

	path := filepath.Join(os.TempDir(), fmt.Sprintf("crowdsec_fp_dump_%s.jsonl", sanitizeFpLabel(label)))

	entry := fpDumpEntry{
		Label:       label,
		Timestamp:   time.Now().UTC(),
		Fingerprint: fp,
	}
	if req != nil {
		entry.RemoteAddr = req.RemoteAddr
		entry.UserAgent = req.Headers.Get("User-Agent")
		entry.Host = req.Host
		entry.URI = req.URI
		entry.Method = req.Method
	}

	line, err := json.Marshal(entry)
	if err != nil {
		log.Errorf("DumpFingerprint(%q): marshal: %s", label, err)
		return ""
	}

	mu := fpDumpLockFor(path)
	mu.Lock()
	defer mu.Unlock()

	fd, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Errorf("DumpFingerprint(%q): open %s: %s", label, path, err)
		return ""
	}
	defer fd.Close()
	if _, err := fd.Write(append(line, '\n')); err != nil {
		log.Errorf("DumpFingerprint(%q): write %s: %s", label, path, err)
		return ""
	}
	log.Infof("fingerprint dumped (label=%q) to %s", label, path)
	return path
}
