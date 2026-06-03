package appsec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
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
//
// IP-naming convention matches the rest of the appsec package: ClientIP
// (json:"client_ip") is the *real* visitor address as the bouncer sees
// it — the field operators actually want when triaging a sample.
// RemoteAddr / RemoteAddrNormalized are the bouncer's own TCP peer,
// preserved for completeness (logged as "bouncer" elsewhere in this
// package — see appsec.go and challenge/fingerprint_helpers.go).
type fpDumpEntry struct {
	Label                string                     `json:"label"`
	Timestamp            time.Time                  `json:"timestamp"`
	ClientIP             string                     `json:"client_ip,omitempty"`
	RemoteAddr           string                     `json:"remote_addr,omitempty"`
	RemoteAddrNormalized string                     `json:"normalized_remote_addr,omitempty"`
	UserAgent            string                     `json:"user_agent,omitempty"`
	Host                 string                     `json:"host,omitempty"`
	URI                  string                     `json:"uri,omitempty"`
	Method               string                     `json:"method,omitempty"`
	Fingerprint          *challenge.FingerprintData `json:"fingerprint"`
}

// DumpFingerprint allows to dump the fingerprint + some context (ip, host, timestamp etc.)
// to as JSONL file for later analysis.
func DumpFingerprint(dir, label string, fp *challenge.FingerprintData, req *ParsedRequest) string {
	if fp == nil {
		log.Warnf("DumpFingerprint(%q) called with nil fingerprint, skipping", label)
		return ""
	}
	if dir == "" {
		log.Warnf("DumpFingerprint(%q): no dump directory configured, skipping", label)
		return ""
	}

	path := filepath.Join(dir, fmt.Sprintf("crowdsec_fp_dump_%s.jsonl", sanitizeFpLabel(label)))

	entry := fpDumpEntry{
		Label:       label,
		Timestamp:   time.Now().UTC(),
		Fingerprint: fp,
	}
	if req != nil {
		entry.ClientIP = req.ClientIP
		entry.RemoteAddr = req.RemoteAddr
		entry.RemoteAddrNormalized = req.RemoteAddrNormalized
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

	// O_NOFOLLOW: refuse to open through a pre-staged symlink. On
	// Linux/Darwin/BSD this is the kernel flag of the same name; on
	// Windows syscall.O_NOFOLLOW is 0 and the call silently degrades —
	// acceptable because Windows isn't a deployment target for the
	// appsec engine and the /tmp threat doesn't apply there.
	fd, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
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
