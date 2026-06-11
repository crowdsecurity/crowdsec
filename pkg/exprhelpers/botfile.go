package exprhelpers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bluele/gcache"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

// legitBotsSubdir is the subdirectory of the data directory holding "bots"
// data files. All files in it are loaded on start/reload (see LoadBotFilesFromDir).
const legitBotsSubdir = "legit_bots"

// dataFileBots holds pre-parsed bot definitions, keyed by filename.
var dataFileBots map[string][]*botEntry

// botEntry is one bot definition (one JSON line in a "bots" data file).
// Matching semantics: (UA && PATH) && (IP || RANGE || RDNS) — the optional
// user_agent and paths regexes are preconditions, then the source must be
// verified by at least one identity check (exact IP, CIDR range, or
// forward-confirmed reverse DNS). UA-only entries are rejected at load time:
// a User-Agent is trivially spoofable.
type botEntry struct {
	Name      string   `json:"name"`
	UserAgent string   `json:"user_agent,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	Ranges    []string `json:"ranges,omitempty"`
	RDNS      []string `json:"rdns,omitempty"`

	// compiled at load time
	uaRegex      *regexp.Regexp
	pathRegexes  []*regexp.Regexp
	ipSet        map[netip.Addr]struct{}
	prefixes     []netip.Prefix
	rdnsSuffixes []string // lowercase, no leading/trailing dot
}

// compileBotRegex compiles a user-supplied bot pattern, case-insensitive by design.
func compileBotRegex(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + pattern)
}

// botFileInit parses a single JSON line of a "bots" data file and appends the
// compiled entry to dataFileBots. All validation is eager so a bad entry
// aborts the load (errors surface at startup, not at request time).
func botFileInit(filename string, line string) error {
	entry := &botEntry{}

	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()

	if err := dec.Decode(entry); err != nil {
		return fmt.Errorf("failed to parse JSON line in %s: %w", filename, err)
	}

	if entry.Name == "" {
		return fmt.Errorf("missing mandatory 'name' field in %s: %s", filename, line)
	}

	if len(entry.IPs)+len(entry.Ranges)+len(entry.RDNS) == 0 {
		return fmt.Errorf("bot entry '%s' in %s has no identity verification (need at least one of ips/ranges/rdns)", entry.Name, filename)
	}

	var err error

	if entry.UserAgent != "" {
		if entry.uaRegex, err = compileBotRegex(entry.UserAgent); err != nil {
			return fmt.Errorf("invalid user_agent regex for bot entry '%s' in %s: %w", entry.Name, filename, err)
		}
	}

	for _, p := range entry.Paths {
		re, err := compileBotRegex(p)
		if err != nil {
			return fmt.Errorf("invalid path regex '%s' for bot entry '%s' in %s: %w", p, entry.Name, filename, err)
		}

		entry.pathRegexes = append(entry.pathRegexes, re)
	}

	entry.ipSet = make(map[netip.Addr]struct{}, len(entry.IPs))

	for _, ip := range entry.IPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return fmt.Errorf("invalid IP '%s' for bot entry '%s' in %s: %w", ip, entry.Name, filename, err)
		}

		entry.ipSet[addr.Unmap()] = struct{}{}
	}

	for _, r := range entry.Ranges {
		prefix, err := netip.ParsePrefix(r)
		if err != nil {
			return fmt.Errorf("invalid CIDR range '%s' for bot entry '%s' in %s: %w", r, entry.Name, filename, err)
		}

		entry.prefixes = append(entry.prefixes, prefix.Masked())
	}

	for _, suffix := range entry.RDNS {
		normalized := strings.Trim(strings.ToLower(suffix), ".")
		if normalized == "" {
			return fmt.Errorf("empty rdns suffix for bot entry '%s' in %s", entry.Name, filename)
		}

		entry.rdnsSuffixes = append(entry.rdnsSuffixes, normalized)
	}

	dataFileBots[filename] = append(dataFileBots[filename], entry)

	return nil
}

// LoadBotFilesFromDir loads every file in <datadir>/legit_bots/ as a "bots"
// data file. Subdirectories and dotfiles are skipped; a missing directory is
// a no-op so the feature is opt-in. A malformed file is logged and skipped
// entirely (no partial definitions), the other files still load — same
// log-and-continue behavior as bucket/parser data files.
func LoadBotFilesFromDir(datadir string) error {
	dir := filepath.Join(datadir, legitBotsSubdir)

	files, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debugf("no %s directory in %s, no bot files to load", legitBotsSubdir, datadir)
			return nil
		}

		return fmt.Errorf("unable to read bot files directory %s: %w", dir, err)
	}

	for _, f := range files {
		if f.IsDir() || strings.HasPrefix(f.Name(), ".") {
			continue
		}

		if err := FileInit(dir, f.Name(), "bots"); err != nil {
			log.Errorf("unable to load bot file '%s': %s", f.Name(), err)
			delete(dataFileBots, f.Name())

			continue
		}

		log.Infof("loaded bot file '%s' (%d entries)", f.Name(), len(dataFileBots[f.Name()]))
	}

	return nil
}

// FCrDNS (forward-confirmed reverse DNS) verification: the PTR record of the
// source IP must forward-resolve back to that same IP. This is the
// documented way to verify Googlebot, Bingbot, etc. Verdicts are cached
// (positive and negative) and concurrent lookups for the same IP coalesce
// via singleflight, so an IP costs at most one PTR+forward chain per TTL.

// dnsResolver is satisfied by *net.Resolver; swapped for a fake in tests.
type dnsResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

var botDNSResolver dnsResolver = net.DefaultResolver

const (
	fcrdnsLookupTimeout = 3 * time.Second // whole PTR+forward chain
	fcrdnsMaxPTRNames   = 3               // PTR fan-out cap; legit bots return 1

	fcrdnsDefaultPositiveTTL = 1 * time.Hour
	fcrdnsDefaultNegativeTTL = 5 * time.Minute
	fcrdnsDefaultCacheSize   = 16384
)

var (
	fcrdnsPositiveTTL = fcrdnsDefaultPositiveTTL
	fcrdnsNegativeTTL = fcrdnsDefaultNegativeTTL
	fcrdnsCacheSize   = fcrdnsDefaultCacheSize

	fcrdnsCacheOnce sync.Once
	fcrdnsCache     gcache.Cache
	fcrdnsSF        singleflight.Group
)

// ConfigureBotDNSCache overrides the FCrDNS cache defaults. Zero values keep
// the current setting. Must be called before the first IsLegitimateBot call
// needing DNS: the cache is built once, on first use.
func ConfigureBotDNSCache(positiveTTL time.Duration, negativeTTL time.Duration, size int) {
	if positiveTTL > 0 {
		fcrdnsPositiveTTL = positiveTTL
	}

	if negativeTTL > 0 {
		fcrdnsNegativeTTL = negativeTTL
	}

	if size > 0 {
		fcrdnsCacheSize = size
	}
}

// purgeBotDNSCache empties the FCrDNS cache. Called from Init for test
// isolation; deliberately NOT called on HUP reload (ResetDataFiles) — DNS
// facts don't change with the configuration, keep the warm entries.
func purgeBotDNSCache() {
	if fcrdnsCache != nil {
		fcrdnsCache.Purge()
	}
}

// fcrdnsVerifiedNames returns the forward-confirmed PTR names of addr:
// PTR lookup, then for each returned name (capped at fcrdnsMaxPTRNames) a
// forward lookup that must contain addr. Names are normalized (lowercase,
// no trailing dot). An empty slice means "no verified name" and is cached
// too, with a shorter TTL.
func fcrdnsVerifiedNames(addr netip.Addr) []string {
	fcrdnsCacheOnce.Do(func() {
		fcrdnsCache = gcache.New(fcrdnsCacheSize).LRU().Build()
	})

	key := addr.String()

	if val, err := fcrdnsCache.Get(key); err == nil {
		return val.([]string)
	}

	val, _, _ := fcrdnsSF.Do(key, func() (any, error) {
		// Re-check the cache inside the singleflight callback in case
		// another goroutine populated it between the fast-path read and
		// our entry into Do.
		if val, err := fcrdnsCache.Get(key); err == nil {
			return val.([]string), nil
		}

		verified := fcrdnsResolve(addr)

		ttl := fcrdnsPositiveTTL
		if len(verified) == 0 {
			ttl = fcrdnsNegativeTTL
		}

		if err := fcrdnsCache.SetWithExpire(key, verified, ttl); err != nil {
			log.Debugf("failed to cache FCrDNS result for %s: %s", key, err)
		}

		return verified, nil
	})

	return val.([]string)
}

// fcrdnsResolve performs the actual (uncached) PTR + forward confirmation.
// It is deliberately detached from any request context: the result is shared
// across requests (singleflight + cache), so one caller's cancellation must
// not abort the lookup for the others. The fixed timeout bounds it instead.
// (contextcheck is excluded for this function in .golangci.yml)
func fcrdnsResolve(addr netip.Addr) []string {
	ctx, cancel := context.WithTimeout(context.Background(), fcrdnsLookupTimeout)
	defer cancel()

	names, err := botDNSResolver.LookupAddr(ctx, addr.String())
	if err != nil {
		log.Debugf("FCrDNS: PTR lookup failed for %s: %s", addr, err)
		return []string{}
	}

	verified := []string{}

	for _, name := range names[:min(len(names), fcrdnsMaxPTRNames)] {
		name = strings.TrimSuffix(strings.ToLower(name), ".")

		ips, err := botDNSResolver.LookupIPAddr(ctx, name)
		if err != nil {
			log.Debugf("FCrDNS: forward lookup failed for %s (PTR of %s): %s", name, addr, err)
			continue
		}

		for _, ip := range ips {
			fwd, ok := netip.AddrFromSlice(ip.IP)
			if ok && fwd.Unmap() == addr {
				verified = append(verified, name)
				break
			}
		}
	}

	return verified
}

// parseBotAddr normalizes a source address as found in HTTP contexts:
// bare IP, "ip:port", "[v6]:port". The zone is stripped and IPv4-mapped
// IPv6 is unmapped so comparisons against load-time-parsed IPs/ranges are
// consistent.
func parseBotAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		host, _, splitErr := net.SplitHostPort(s)
		if splitErr != nil {
			return netip.Addr{}, false
		}

		if addr, err = netip.ParseAddr(host); err != nil {
			return netip.Addr{}, false
		}
	}

	return addr.WithZone("").Unmap(), true
}

// domainSuffixMatch reports whether name equals suffix or is a subdomain of
// it. The label-boundary check prevents "evilgooglebot.com" from matching
// the suffix "googlebot.com".
func domainSuffixMatch(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}

	return false
}

// IsLegitimateBot reports whether the request (source address, User-Agent,
// path) matches a bot definition from the loaded "bots" data files:
// (UA && PATH) && (IP || RANGE || RDNS). Fail-closed: an unparseable
// address or a DNS failure means "not a legitimate bot", never an error.
//
// The expensive FCrDNS resolution runs at most once per call — after the
// cheap checks, against all candidate entries at once — and is cached per IP.
func IsLegitimateBot(ip string, ua string, path string) bool {
	if len(dataFileBots) == 0 {
		return false
	}

	addr, ok := parseBotAddr(ip)
	if !ok {
		log.Debugf("IsLegitimateBot: invalid source address '%s'", ip)
		return false
	}

	var rdnsCandidates []*botEntry

	for _, entries := range dataFileBots {
		for _, entry := range entries {
			if entry.uaRegex != nil && !entry.uaRegex.MatchString(ua) {
				continue
			}

			if len(entry.pathRegexes) > 0 && !matchAnyRegex(entry.pathRegexes, path) {
				continue
			}

			if _, found := entry.ipSet[addr]; found {
				log.Debugf("IsLegitimateBot: %s verified as '%s' via exact IP", ip, entry.Name)
				return true
			}

			for _, prefix := range entry.prefixes {
				if prefix.Contains(addr) {
					log.Debugf("IsLegitimateBot: %s verified as '%s' via range %s", ip, entry.Name, prefix)
					return true
				}
			}

			if len(entry.rdnsSuffixes) > 0 {
				rdnsCandidates = append(rdnsCandidates, entry)
			}
		}
	}

	if len(rdnsCandidates) == 0 {
		return false
	}

	for _, name := range fcrdnsVerifiedNames(addr) {
		for _, entry := range rdnsCandidates {
			if domainSuffixMatch(name, entry.rdnsSuffixes) {
				log.Debugf("IsLegitimateBot: %s verified as '%s' via FCrDNS (%s)", ip, entry.Name, name)
				return true
			}
		}
	}

	return false
}

func matchAnyRegex(regexes []*regexp.Regexp, s string) bool {
	for _, re := range regexes {
		if re.MatchString(s) {
			return true
		}
	}

	return false
}
