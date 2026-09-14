// Package dnscache provides process-wide cached DNS lookups: PTR records,
// forward (A/AAAA) records, and forward-confirmed reverse DNS (FCrDNS)
// composed from the two. Results — including failures — are cached in a
// shared LRU, and concurrent lookups for the same key coalesce via
// singleflight, so a given DNS fact costs at most one query per TTL.
//
// Consumers: the parser's reverse_dns enricher (PTR only) and the
// MatchKnownBot expr helper (FCrDNS).
package dnscache

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bluele/gcache"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

// Resolver is satisfied by *net.Resolver; swapped for a fake in tests.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

var resolver Resolver = net.DefaultResolver

func SetResolver(r Resolver) {
	resolver = r
}

const (
	lookupTimeout = 3 * time.Second // per lookup (PTR or forward)
	maxPTRNames   = 3               // PTR fan-out cap; legit hosts return 1

	defaultPositiveTTL = 1 * time.Hour
	defaultNegativeTTL = 5 * time.Minute
	defaultCacheSize   = 16384
)

var (
	positiveTTL = defaultPositiveTTL
	negativeTTL = defaultNegativeTTL
	cacheSize   = defaultCacheSize

	cacheOnce sync.Once
	cache     gcache.Cache
	sf        singleflight.Group
)

func Configure(posTTL time.Duration, negTTL time.Duration, size int) {
	if posTTL > 0 {
		positiveTTL = posTTL
	}

	if negTTL > 0 {
		negativeTTL = negTTL
	}

	if size > 0 {
		cacheSize = size
	}
}

func Purge() {
	if cache != nil {
		cache.Purge()
	}
}

func cachedLookup[T any](key string, lookup func() T, empty func(T) bool) T {
	cacheOnce.Do(func() {
		cache = gcache.New(cacheSize).LRU().Build()
	})

	if val, err := cache.Get(key); err == nil {
		return val.(T)
	}

	val, _, _ := sf.Do(key, func() (any, error) {
		// Re-check the cache inside the singleflight callback in case
		// another goroutine populated it between the fast-path read and
		// our entry into Do.
		if val, err := cache.Get(key); err == nil {
			return val.(T), nil
		}

		result := lookup()

		ttl := positiveTTL
		if empty(result) {
			ttl = negativeTTL
		}

		if err := cache.SetWithExpire(key, result, ttl); err != nil {
			log.Debugf("failed to cache DNS result for %s: %s", key, err)
		}

		return result, nil
	})

	return val.(T)
}

func PTRRecords(addr netip.Addr) []string {
	return cachedLookup("ptr:"+addr.String(), func() []string {
		return lookupPTR(addr)
	}, func(names []string) bool { return len(names) == 0 })
}

func ForwardIPs(host string) []netip.Addr {
	host = strings.TrimSuffix(strings.ToLower(host), ".")

	return cachedLookup("fwd:"+host, func() []netip.Addr {
		return lookupForward(host)
	}, func(ips []netip.Addr) bool { return len(ips) == 0 })
}

func ForwardConfirmedNames(addr netip.Addr) []string {
	verified := []string{}

	names := PTRRecords(addr)

	for _, name := range names[:min(len(names), maxPTRNames)] {
		name = strings.TrimSuffix(strings.ToLower(name), ".")

		if slices.Contains(ForwardIPs(name), addr.Unmap()) {
			verified = append(verified, name)
		}
	}

	return verified
}

func lookupPTR(addr netip.Addr) []string {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	names, err := resolver.LookupAddr(ctx, addr.String())
	if err != nil {
		log.Debugf("dnscache: PTR lookup failed for %s: %s", addr, err)
		return []string{}
	}

	return names
}

func lookupForward(host string) []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		log.Debugf("dnscache: forward lookup failed for %s: %s", host, err)
		return []netip.Addr{}
	}

	addrs := []netip.Addr{}

	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip.IP); ok {
			addrs = append(addrs, addr.Unmap())
		}
	}

	return addrs
}
