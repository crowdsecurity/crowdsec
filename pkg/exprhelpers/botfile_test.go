package exprhelpers

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/dnscache"
)

// fakeResolver implements dnscache.Resolver from in-memory maps so no test
// ever hits real DNS. ptrCalls lets tests assert how many lookups ran.
// (The cache/singleflight internals are tested in pkg/dnscache; here the
// fake only backs the end-to-end MatchKnownBot checks.)
type fakeResolver struct {
	ptr      map[string][]string     // ip → PTR names
	fwd      map[string][]net.IPAddr // hostname → addresses
	ptrCalls atomic.Int32
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.ptrCalls.Add(1)

	names, ok := f.ptr[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}

	return names, nil
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := f.fwd[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	return ips, nil
}

// setupBotTest resets the datafile globals and, when a fake resolver is
// given, installs it in pkg/dnscache with an empty cache for isolation.
func setupBotTest(t *testing.T, resolver *fakeResolver) {
	t.Helper()

	err := Init(nil)
	require.NoError(t, err)

	if resolver != nil {
		dnscache.SetResolver(resolver)
		dnscache.Purge()
		t.Cleanup(func() {
			dnscache.SetResolver(net.DefaultResolver)
			dnscache.Purge()
		})
	}
}

func TestBotFileInit(t *testing.T) {
	setupBotTest(t, nil)

	err := FileInit("testdata", "test_data_bots.json", "bots")
	require.NoError(t, err)

	entries, ok := dataFileBots["test_data_bots.json"]
	require.True(t, ok, "test_data_bots.json should be loaded")
	require.Len(t, entries, 4, "should have 4 entries (skipping comment and empty line)")

	googlebot := entries[0]
	assert.Equal(t, "googlebot", googlebot.Name)
	assert.NotNil(t, googlebot.uaRegex)
	assert.Empty(t, googlebot.pathRegexes)
	assert.Len(t, googlebot.rdnsRegexes, 2)

	uptimerobot := entries[1]
	assert.Len(t, uptimerobot.pathRegexes, 2)
	assert.Len(t, uptimerobot.prefixes, 2)
	assert.Len(t, uptimerobot.ipSet, 1)

	// double load is a no-op, not an error
	err = FileInit("testdata", "test_data_bots.json", "bots")
	require.NoError(t, err)
	assert.Len(t, dataFileBots["test_data_bots.json"], 4)
}

func TestBotFileInitErrors(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		expectedErr string
	}{
		{"invalid JSON", "test_data_bots_invalid.json", "failed to parse JSON line"},
		{"missing name", "test_data_bots_no_name.json", "missing mandatory 'name' field"},
		{"no identity check", "test_data_bots_no_identity.json", "no identity verification"},
		{"bad user_agent regex", "test_data_bots_bad_regex.json", "invalid user_agent regex"},
		{"bad rdns regex", "test_data_bots_bad_rdns.json", "invalid rdns regex"},
		{"bad CIDR", "test_data_bots_bad_cidr.json", "invalid CIDR range"},
		{"bad IP", "test_data_bots_bad_ip.json", "invalid IP"},
		{"unknown field", "test_data_bots_unknown_field.json", "unknown field"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setupBotTest(t, nil)

			err := FileInit("testdata", tc.filename, "bots")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

func TestBotFileUnknownType(t *testing.T) {
	setupBotTest(t, nil)

	// singular "bot" is a typo, must be rejected by existsInFileMaps
	err := FileInit("testdata", "test_data_bots.json", "bot")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown data type")
}

func TestMatchKnownBotNoDNS(t *testing.T) {
	resolver := &fakeResolver{}
	setupBotTest(t, resolver)

	err := FileInit("testdata", "test_data_bots.json", "bots")
	require.NoError(t, err)

	tests := []struct {
		name     string
		ip       string
		ua       string
		path     string
		expected bool
	}{
		{"exact IP", "10.1.2.3", "", "/", true},
		{"exact IPv6", "2001:db8::42", "", "/", true},
		{"exact IP with port", "10.1.2.3:54321", "", "/", true},
		{"IPv4-mapped IPv6", "::ffff:10.1.2.3", "", "/", true},
		{"range hit", "192.0.2.77", "anything", "/any/path", true},
		{"range miss", "192.0.3.77", "anything", "/any/path", false},
		{"UA+path+range", "69.162.124.230", "UptimeRobot/2.0", "/health/db", true},
		{"UA+path+IP", "216.144.250.150", "uptimerobot", "/status", true},
		{"UA+path+v6 range with port", "[2607:ff68:107::25]:443", "UptimeRobot/2.0", "/health", true},
		{"UA case-insensitive", "69.162.124.230", "UPTIMEROBOT", "/health", true},
		{"path case-insensitive", "69.162.124.230", "uptimerobot", "/HEALTH", true},
		{"path mismatch", "69.162.124.230", "uptimerobot", "/index.html", false},
		{"UA mismatch", "69.162.124.230", "definitely-not-it", "/health", false},
		{"empty UA against UA filter", "69.162.124.230", "", "/health", false},
		{"garbage IP", "not-an-ip", "uptimerobot", "/health", false},
		{"empty IP", "", "uptimerobot", "/health", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, MatchKnownBot(tc.ip, tc.ua, tc.path, "test_data_bots.json"))
		})
	}

	// none of the above may have triggered a DNS lookup: either they matched
	// on IP/range, or they failed a precondition / address parsing.
	// "range miss" and "path/UA mismatch" don't reach the googlebot entry's
	// rdns because its UA precondition doesn't match those UAs.
	assert.Equal(t, int32(0), resolver.ptrCalls.Load(), "no DNS lookup expected")
}

func TestMatchKnownBotNoFiles(t *testing.T) {
	resolver := &fakeResolver{}
	setupBotTest(t, resolver)

	// nothing loaded, and an unknown filename must fail closed without DNS
	assert.False(t, MatchKnownBot("10.1.2.3", "googlebot", "/", "test_data_bots.json"))
	assert.Equal(t, int32(0), resolver.ptrCalls.Load())
}

func TestMatchKnownBotFCrDNS(t *testing.T) {
	tests := []struct {
		name     string
		resolver *fakeResolver
		ip       string
		ua       string
		expected bool
	}{
		{
			name: "happy path, trailing dot and mixed case PTR",
			resolver: &fakeResolver{
				ptr: map[string][]string{"66.249.66.1": {"Crawl-66-249-66-1.GoogleBot.com."}},
				fwd: map[string][]net.IPAddr{"crawl-66-249-66-1.googlebot.com": {{IP: net.ParseIP("66.249.66.1")}}},
			},
			ip:       "66.249.66.1",
			ua:       "Mozilla/5.0 (compatible; Googlebot/2.1)",
			expected: true,
		},
		{
			name: "spoofed PTR, forward lookup does not confirm",
			resolver: &fakeResolver{
				ptr: map[string][]string{"203.0.113.5": {"crawl.googlebot.com."}},
				fwd: map[string][]net.IPAddr{"crawl.googlebot.com": {{IP: net.ParseIP("66.249.66.1")}}},
			},
			ip:       "203.0.113.5",
			ua:       "googlebot",
			expected: false,
		},
		{
			name: "anchored pattern rejects lookalike domain",
			resolver: &fakeResolver{
				ptr: map[string][]string{"203.0.113.6": {"evilgooglebot.com."}},
				fwd: map[string][]net.IPAddr{"evilgooglebot.com": {{IP: net.ParseIP("203.0.113.6")}}},
			},
			ip:       "203.0.113.6",
			ua:       "googlebot",
			expected: false,
		},
		{
			name: "no PTR record",
			resolver: &fakeResolver{
				ptr: map[string][]string{},
			},
			ip:       "203.0.113.7",
			ua:       "googlebot",
			expected: false,
		},
		{
			name: "forward confirms via second domain suffix",
			resolver: &fakeResolver{
				ptr: map[string][]string{"66.249.66.2": {"rate-limited-proxy.google.com."}},
				fwd: map[string][]net.IPAddr{"rate-limited-proxy.google.com": {{IP: net.ParseIP("66.249.66.2")}}},
			},
			ip:       "66.249.66.2",
			ua:       "googlebot",
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setupBotTest(t, tc.resolver)

			err := FileInit("testdata", "test_data_bots.json", "bots")
			require.NoError(t, err)

			assert.Equal(t, tc.expected, MatchKnownBot(tc.ip, tc.ua, "/", "test_data_bots.json"))
		})
	}
}

func TestMatchKnownBotDNSCache(t *testing.T) {
	resolver := &fakeResolver{
		ptr: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		fwd: map[string][]net.IPAddr{"crawl-66-249-66-1.googlebot.com": {{IP: net.ParseIP("66.249.66.1")}}},
	}
	setupBotTest(t, resolver)

	err := FileInit("testdata", "test_data_bots.json", "bots")
	require.NoError(t, err)

	assert.True(t, MatchKnownBot("66.249.66.1", "googlebot", "/", "test_data_bots.json"))
	assert.True(t, MatchKnownBot("66.249.66.1", "googlebot", "/other", "test_data_bots.json"))
	assert.Equal(t, int32(1), resolver.ptrCalls.Load(), "second call must be served from cache")

	// negative results are cached too
	assert.False(t, MatchKnownBot("203.0.113.9", "googlebot", "/", "test_data_bots.json"))
	assert.False(t, MatchKnownBot("203.0.113.9", "googlebot", "/", "test_data_bots.json"))
	assert.Equal(t, int32(2), resolver.ptrCalls.Load(), "failed lookup must be cached as negative")
}

// bot data files are loaded per-file via FileInit(dir, name, "bots"), driven
// by the data reference on each appsec-config (see LoadCollection / Build).
func TestFileInitBots(t *testing.T) {
	setupBotTest(t, nil)

	botsDir := t.TempDir()

	write := func(name, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(botsDir, name), []byte(content), 0o644))
	}

	write("google.json", `{"name":"googlebot","user_agent":"googlebot","rdns":["googlebot.com"]}`)
	write("partners.json", `{"name":"partner","ranges":["192.0.2.0/24"]}`)

	require.NoError(t, FileInit(botsDir, "google.json", "bots"))
	require.NoError(t, FileInit(botsDir, "partners.json", "bots"))

	assert.Len(t, dataFileBots, 2)
	assert.Contains(t, dataFileBots, "google.json")
	assert.Contains(t, dataFileBots, "partners.json")

	// MatchKnownBot is scoped to the named files: the partner entry only
	// matches when partners.json is queried.
	assert.False(t, MatchKnownBot("192.0.2.10", "", "/", "google.json"))
	assert.True(t, MatchKnownBot("192.0.2.10", "", "/", "partners.json"))
	// multiple files in one call: match if any of them matches
	assert.True(t, MatchKnownBot("192.0.2.10", "", "/", "google.json", "partners.json"))
}

func TestFileInitBotsInvalidFile(t *testing.T) {
	setupBotTest(t, nil)

	botsDir := t.TempDir()
	// first line is valid, second has no identity verification: the
	// malformed line makes the whole load fail.
	require.NoError(t, os.WriteFile(filepath.Join(botsDir, "bad.json"),
		[]byte(`{"name":"ok","ips":["10.0.0.1"]}`+"\n"+`{"name":"ua-only","user_agent":"x"}`), 0o644))

	require.Error(t, FileInit(botsDir, "bad.json", "bots"))
}

func TestParseBotAddr(t *testing.T) {
	tests := []struct {
		in       string
		expected string
		ok       bool
	}{
		{"1.2.3.4", "1.2.3.4", true},
		{"1.2.3.4:8080", "1.2.3.4", true},
		{"2001:db8::1", "2001:db8::1", true},
		{"[2001:db8::1]:443", "2001:db8::1", true},
		{"::ffff:1.2.3.4", "1.2.3.4", true},
		{"fe80::1%eth0", "fe80::1", true},
		{"garbage", "", false},
		{"", "", false},
		{"1.2.3.4:port:extra", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			addr, ok := parseBotAddr(tc.in)
			assert.Equal(t, tc.ok, ok)

			if tc.ok {
				assert.Equal(t, tc.expected, addr.String())
			}
		})
	}
}
