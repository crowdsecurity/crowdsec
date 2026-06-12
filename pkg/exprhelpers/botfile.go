package exprhelpers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/dnscache"
)

const legitBotsSubdir = "legit_bots"

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

func compileBotRegex(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + pattern) // Force case insensitive match
}

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

	for _, name := range dnscache.ForwardConfirmedNames(addr) {
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
