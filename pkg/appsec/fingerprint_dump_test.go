package appsec

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
)

// fakeFingerprint returns a minimal but distinguishable *challenge.FingerprintData
// suitable for asserting that DumpFingerprint preserved the value end-to-end.
func fakeFingerprint(fsid string) *challenge.FingerprintData {
	return &challenge.FingerprintData{
		FSID:  fsid,
		Nonce: "test-nonce",
		Time:  1717000000,
		URL:   "https://example.test/path",
	}
}

func fakeRequest() *ParsedRequest {
	return &ParsedRequest{
		// Distinct visitor vs. bouncer addresses so the test can prove
		// DumpFingerprint records the *real* source IP (ClientIP) and
		// not just the bouncer's TCP peer (RemoteAddr).
		ClientIP:             "203.0.113.7",
		RemoteAddr:           "127.0.0.1:54321",
		RemoteAddrNormalized: "127.0.0.1",
		Host:                 "example.test",
		URI:                  "/login",
		Method:               "POST",
		Headers:              http.Header{"User-Agent": []string{"Mozilla/5.0 (test)"}},
	}
}

// readJSONL reads every line of the given path as a JSON object and returns them.
func readJSONL(t *testing.T, path string) []map[string]any {
	t.Helper()
	fd, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %s", path, err)
	}
	defer fd.Close()
	var out []map[string]any
	sc := bufio.NewScanner(fd)
	// Fingerprints with full signals can be large; bump the buffer to avoid
	// false negatives on real-shape payloads, even though our test data is tiny.
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("invalid JSON line %q: %s", sc.Text(), err)
		}
		out = append(out, m)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %s", err)
	}
	return out
}

func TestSanitizeFpLabel(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"bot", "bot"},
		{"human – Chrome on macOS!", "human_chrome_on_macos"},
		{"   ", "unlabeled"},
		{"", "unlabeled"},
		{"!!! @@@ ", "unlabeled"},
		{"Bot-1", "bot_1"},
		{"Bot_1", "bot_1"},
		// 50-char alpha label gets truncated to 40, trim of trailing underscore is a no-op.
		{strings.Repeat("a", 50), strings.Repeat("a", 40)},
	}
	for _, tc := range cases {
		got := sanitizeFpLabel(tc.in)
		if got != tc.want {
			t.Errorf("sanitizeFpLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDumpFingerprint_AppendsAndPreservesFields(t *testing.T) {
	dir := t.TempDir()
	fp := fakeFingerprint("fsid-abc")
	req := fakeRequest()

	path1 := DumpFingerprint(dir, "test-human", fp, req)
	if path1 == "" {
		t.Fatal("first DumpFingerprint returned empty path")
	}
	wantPath := filepath.Join(dir, "crowdsec_fp_dump_test_human.jsonl")
	if path1 != wantPath {
		t.Errorf("path = %q, want %q", path1, wantPath)
	}

	// Second call with the same label must append, not truncate.
	path2 := DumpFingerprint(dir, "test-human", fakeFingerprint("fsid-def"), req)
	if path2 != path1 {
		t.Errorf("second call wrote to %q, want same file %q", path2, path1)
	}

	lines := readJSONL(t, path1)
	if len(lines) != 2 {
		t.Fatalf("got %d JSONL lines, want 2 (append failed?)", len(lines))
	}

	// Both lines must carry the operator-supplied label verbatim.
	for i, line := range lines {
		if line["label"] != "test-human" {
			t.Errorf("line %d label = %v, want %q", i, line["label"], "test-human")
		}
		// Timestamp must parse as RFC3339.
		ts, ok := line["timestamp"].(string)
		if !ok {
			t.Errorf("line %d timestamp not a string: %T", i, line["timestamp"])
		} else if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
			t.Errorf("line %d timestamp %q not RFC3339: %s", i, ts, err)
		}
		// Minimal request context preserved.
		// client_ip is the real visitor address — the field a SOC
		// operator actually wants when triaging a sample. Verify it
		// is distinct from remote_addr (which is the bouncer).
		if line["client_ip"] != "203.0.113.7" {
			t.Errorf("line %d client_ip = %v, want %q", i, line["client_ip"], "203.0.113.7")
		}
		if line["remote_addr"] != "127.0.0.1:54321" {
			t.Errorf("line %d remote_addr = %v", i, line["remote_addr"])
		}
		if line["normalized_remote_addr"] != "127.0.0.1" {
			t.Errorf("line %d normalized_remote_addr = %v", i, line["normalized_remote_addr"])
		}
		if line["user_agent"] != "Mozilla/5.0 (test)" {
			t.Errorf("line %d user_agent = %v", i, line["user_agent"])
		}
		if line["host"] != "example.test" {
			t.Errorf("line %d host = %v", i, line["host"])
		}
		if line["uri"] != "/login" {
			t.Errorf("line %d uri = %v", i, line["uri"])
		}
		if line["method"] != "POST" {
			t.Errorf("line %d method = %v", i, line["method"])
		}
	}

	// Fingerprint payload must be preserved per-line (fsid differs across the two calls).
	wantFSIDs := []string{"fsid-abc", "fsid-def"}
	for i, line := range lines {
		fp, ok := line["fingerprint"].(map[string]any)
		if !ok {
			t.Fatalf("line %d: fingerprint not an object: %T", i, line["fingerprint"])
		}
		if fp["fsid"] != wantFSIDs[i] {
			t.Errorf("line %d fingerprint.fsid = %v, want %q", i, fp["fsid"], wantFSIDs[i])
		}
	}
}

func TestDumpFingerprint_DifferentLabelsGoToDifferentFiles(t *testing.T) {
	dir := t.TempDir()
	pHuman := DumpFingerprint(dir, "human", fakeFingerprint("a"), fakeRequest())
	pBot := DumpFingerprint(dir, "bot", fakeFingerprint("b"), fakeRequest())
	if pHuman == "" || pBot == "" {
		t.Fatalf("paths empty: %q %q", pHuman, pBot)
	}
	if pHuman == pBot {
		t.Fatalf("expected distinct files for distinct labels, got %q", pHuman)
	}

	if got := len(readJSONL(t, pHuman)); got != 1 {
		t.Errorf("human file has %d lines, want 1", got)
	}
	if got := len(readJSONL(t, pBot)); got != 1 {
		t.Errorf("bot file has %d lines, want 1", got)
	}
}

func TestDumpFingerprint_NilFingerprintIsNoop(t *testing.T) {
	dir := t.TempDir()
	got := DumpFingerprint(dir, "anything", nil, fakeRequest())
	if got != "" {
		t.Errorf("nil fingerprint returned path %q, want empty", got)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "crowdsec_fp_dump_") {
			t.Errorf("nil fingerprint wrote a file: %s", e.Name())
		}
	}
}

// TestDumpFingerprint_EmptyDirIsNoop is the regression guard for the
// /tmp-fallback temptation: an operator running with FingerprintDumpDir
// unset (e.g. engine couldn't MkdirAll the data-dir subdir at startup)
// must get a logged no-op, not a silent write to os.TempDir(). The whole
// reason the dir is configurable is that /tmp is unsafe.
func TestDumpFingerprint_EmptyDirIsNoop(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp) // belt-and-braces: prove no /tmp fallback fired

	got := DumpFingerprint("", "anything", fakeFingerprint("xx"), fakeRequest())
	if got != "" {
		t.Errorf("empty dir returned path %q, want empty", got)
	}

	// Neither the test TempDir() (used as TMPDIR) nor the system temp dir
	// should have grown a dump file.
	for _, scanDir := range []string{tmp, os.TempDir()} {
		entries, err := os.ReadDir(scanDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "crowdsec_fp_dump_") {
				t.Errorf("empty dir caused a fallback write: %s/%s", scanDir, e.Name())
			}
		}
	}
}

func TestDumpFingerprint_NilRequestStillDumps(t *testing.T) {
	dir := t.TempDir()
	path := DumpFingerprint(dir, "nofreq", fakeFingerprint("xx"), nil)
	if path == "" {
		t.Fatal("expected dump to succeed with nil request")
	}
	lines := readJSONL(t, path)
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	// Request fields are omitempty, so they should be absent from the JSON.
	for _, k := range []string{"client_ip", "remote_addr", "normalized_remote_addr", "user_agent", "host", "uri", "method"} {
		if _, ok := lines[0][k]; ok {
			t.Errorf("nil request still wrote %s=%v", k, lines[0][k])
		}
	}
}

func TestDumpFingerprint_EmptyAndJunkLabelsCollapse(t *testing.T) {
	dir := t.TempDir()
	p1 := DumpFingerprint(dir, "", fakeFingerprint("a"), nil)
	p2 := DumpFingerprint(dir, "!!! @@@ ", fakeFingerprint("b"), nil)
	if p1 == "" || p2 == "" {
		t.Fatalf("paths empty: %q %q", p1, p2)
	}
	wantPath := filepath.Join(dir, "crowdsec_fp_dump_unlabeled.jsonl")
	if p1 != wantPath || p2 != wantPath {
		t.Errorf("expected both junk labels to land in %q, got %q and %q", wantPath, p1, p2)
	}
	if got := len(readJSONL(t, p1)); got != 2 {
		t.Errorf("unlabeled file has %d lines, want 2", got)
	}
}

func TestDumpFingerprint_ConcurrentAppendIsLineSafe(t *testing.T) {
	dir := t.TempDir()
	const goroutines = 32
	const perGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				if path := DumpFingerprint(dir, "race", fakeFingerprint("fsid"), fakeRequest()); path == "" {
					t.Errorf("DumpFingerprint returned empty path under contention")
					return
				}
			}
		}()
	}
	wg.Wait()

	path := filepath.Join(dir, "crowdsec_fp_dump_race.jsonl")
	lines := readJSONL(t, path) // this would fatal on any torn line
	if len(lines) != goroutines*perGoroutine {
		t.Errorf("got %d lines, want %d", len(lines), goroutines*perGoroutine)
	}
}

// TestDumpFingerprint_RefusesSymlink is the core security regression
// guard: even if an attacker somehow lands a symlink inside the
// dedicated dump dir (0o700 makes this hard but not impossible — think
// shared-tenant container hosts, mis-set umasks, restore-from-backup
// races), the open must abort instead of writing through the link to
// the symlink's target. Skipped on Windows where O_NOFOLLOW is 0 and
// /tmp wasn't a threat anyway.
func TestDumpFingerprint_RefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("O_NOFOLLOW is a no-op on Windows; the /tmp symlink threat doesn't apply there")
	}

	dir := t.TempDir()
	// The "victim" file the attacker wants DumpFingerprint to clobber.
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "sensitive.log")
	if err := os.WriteFile(victim, []byte("ORIGINAL\n"), 0o600); err != nil {
		t.Fatalf("seed victim: %s", err)
	}

	// Pre-stage the symlink at the exact path DumpFingerprint will compute
	// for label "test-human".
	dumpPath := filepath.Join(dir, "crowdsec_fp_dump_test_human.jsonl")
	if err := os.Symlink(victim, dumpPath); err != nil {
		t.Fatalf("pre-stage symlink: %s", err)
	}

	got := DumpFingerprint(dir, "test-human", fakeFingerprint("xx"), fakeRequest())
	if got != "" {
		t.Errorf("DumpFingerprint followed the symlink and returned %q; expected empty (refusal)", got)
	}

	// Victim file content must be untouched.
	body, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("read victim: %s", err)
	}
	if string(body) != "ORIGINAL\n" {
		t.Errorf("victim was clobbered through the symlink: %q", body)
	}
}
