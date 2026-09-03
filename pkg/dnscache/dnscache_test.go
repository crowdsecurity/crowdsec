package dnscache

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeResolver implements Resolver from in-memory maps so no test ever hits
// real DNS. ptrCalls/fwdCalls let tests assert how many lookups ran.
type fakeResolver struct {
	ptr      map[string][]string     // ip → PTR names
	fwd      map[string][]net.IPAddr // hostname → addresses
	delay    time.Duration
	ptrCalls atomic.Int32
	fwdCalls atomic.Int32
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.ptrCalls.Add(1)
	time.Sleep(f.delay)

	names, ok := f.ptr[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}

	return names, nil
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.fwdCalls.Add(1)

	ips, ok := f.fwd[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	return ips, nil
}

// setupDNSTest installs the fake resolver and guarantees an empty cache,
// restoring the default resolver when the test ends.
func setupDNSTest(t *testing.T, r *fakeResolver) {
	t.Helper()

	SetResolver(r)
	Purge()
	t.Cleanup(func() {
		SetResolver(net.DefaultResolver)
		Purge()
	})
}

func TestPTRRecordsRawNames(t *testing.T) {
	resolver := &fakeResolver{
		ptr: map[string][]string{"1.1.1.1": {"One.One.one.one."}},
	}
	setupDNSTest(t, resolver)

	// names come back raw: trailing dot and case preserved (the reverse_dns
	// parser enricher exposes them as-is)
	assert.Equal(t, []string{"One.One.one.one."}, PTRRecords(netip.MustParseAddr("1.1.1.1")))

	// failures return an empty slice, and are cached too
	assert.Empty(t, PTRRecords(netip.MustParseAddr("203.0.113.1")))
	assert.Empty(t, PTRRecords(netip.MustParseAddr("203.0.113.1")))
	assert.Equal(t, int32(2), resolver.ptrCalls.Load(), "failed lookup must be cached as negative")
}

func TestForwardIPsKeyNormalization(t *testing.T) {
	resolver := &fakeResolver{
		fwd: map[string][]net.IPAddr{"host.example.com": {{IP: net.ParseIP("192.0.2.1")}}},
	}
	setupDNSTest(t, resolver)

	want := []netip.Addr{netip.MustParseAddr("192.0.2.1")}

	// trailing dot and case variants hit the same cache entry
	assert.Equal(t, want, ForwardIPs("Host.Example.COM."))
	assert.Equal(t, want, ForwardIPs("host.example.com"))
	assert.Equal(t, int32(1), resolver.fwdCalls.Load(), "normalized variants must share one cache entry")
}

func TestForwardConfirmedNames(t *testing.T) {
	tests := []struct {
		name     string
		resolver *fakeResolver
		ip       string
		expected []string
	}{
		{
			name: "happy path, trailing dot and mixed case PTR",
			resolver: &fakeResolver{
				ptr: map[string][]string{"66.249.66.1": {"Crawl-66-249-66-1.GoogleBot.com."}},
				fwd: map[string][]net.IPAddr{"crawl-66-249-66-1.googlebot.com": {{IP: net.ParseIP("66.249.66.1")}}},
			},
			ip:       "66.249.66.1",
			expected: []string{"crawl-66-249-66-1.googlebot.com"},
		},
		{
			name: "spoofed PTR, forward lookup does not confirm",
			resolver: &fakeResolver{
				ptr: map[string][]string{"203.0.113.5": {"crawl.googlebot.com."}},
				fwd: map[string][]net.IPAddr{"crawl.googlebot.com": {{IP: net.ParseIP("66.249.66.1")}}},
			},
			ip:       "203.0.113.5",
			expected: []string{},
		},
		{
			name:     "no PTR record",
			resolver: &fakeResolver{},
			ip:       "203.0.113.7",
			expected: []string{},
		},
		{
			name: "PTR fan-out capped, extra names ignored",
			resolver: &fakeResolver{
				ptr: map[string][]string{"203.0.113.8": {"a.example.com.", "b.example.com.", "c.example.com.", "d.example.com."}},
				fwd: map[string][]net.IPAddr{"d.example.com": {{IP: net.ParseIP("203.0.113.8")}}},
			},
			ip:       "203.0.113.8",
			expected: []string{},
		},
		{
			name: "IPv4-mapped forward answer still confirms",
			resolver: &fakeResolver{
				ptr: map[string][]string{"192.0.2.9": {"mapped.example.com."}},
				fwd: map[string][]net.IPAddr{"mapped.example.com": {{IP: net.ParseIP("192.0.2.9").To16()}}},
			},
			ip:       "192.0.2.9",
			expected: []string{"mapped.example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setupDNSTest(t, tc.resolver)
			assert.Equal(t, tc.expected, ForwardConfirmedNames(netip.MustParseAddr(tc.ip)))
		})
	}
}

func TestForwardConfirmedNamesSharesPTRCache(t *testing.T) {
	resolver := &fakeResolver{
		ptr: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		fwd: map[string][]net.IPAddr{"crawl-66-249-66-1.googlebot.com": {{IP: net.ParseIP("66.249.66.1")}}},
	}
	setupDNSTest(t, resolver)

	addr := netip.MustParseAddr("66.249.66.1")

	// a plain PTR consumer warms the cache for the FCrDNS consumer
	require.NotEmpty(t, PTRRecords(addr))
	assert.Equal(t, []string{"crawl-66-249-66-1.googlebot.com"}, ForwardConfirmedNames(addr))
	assert.Equal(t, int32(1), resolver.ptrCalls.Load(), "FCrDNS must reuse the cached PTR entry")

	// and the composed result is fully cached on repeat
	assert.Equal(t, []string{"crawl-66-249-66-1.googlebot.com"}, ForwardConfirmedNames(addr))
	assert.Equal(t, int32(1), resolver.ptrCalls.Load())
	assert.Equal(t, int32(1), resolver.fwdCalls.Load())
}

func TestSingleflight(t *testing.T) {
	resolver := &fakeResolver{
		ptr:   map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		fwd:   map[string][]net.IPAddr{"crawl-66-249-66-1.googlebot.com": {{IP: net.ParseIP("66.249.66.1")}}},
		delay: 50 * time.Millisecond,
	}
	setupDNSTest(t, resolver)

	addr := netip.MustParseAddr("66.249.66.1")

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			assert.Equal(t, []string{"crawl-66-249-66-1.googlebot.com"}, ForwardConfirmedNames(addr))
		})
	}

	wg.Wait()
	assert.Equal(t, int32(1), resolver.ptrCalls.Load(), "concurrent cold lookups must coalesce")
}

func TestConfigureZeroValuesKeepDefaults(t *testing.T) {
	t.Cleanup(func() {
		positiveTTL = defaultPositiveTTL
		negativeTTL = defaultNegativeTTL
		cacheSize = defaultCacheSize
	})

	Configure(0, 0, 0)
	assert.Equal(t, defaultPositiveTTL, positiveTTL)
	assert.Equal(t, defaultNegativeTTL, negativeTTL)
	assert.Equal(t, defaultCacheSize, cacheSize)

	Configure(2*time.Hour, 0, 0)
	assert.Equal(t, 2*time.Hour, positiveTTL)
	assert.Equal(t, defaultNegativeTTL, negativeTTL)
	assert.Equal(t, defaultCacheSize, cacheSize)

	Configure(0, 10*time.Minute, 4096)
	assert.Equal(t, 2*time.Hour, positiveTTL)
	assert.Equal(t, 10*time.Minute, negativeTTL)
	assert.Equal(t, 4096, cacheSize)
}
