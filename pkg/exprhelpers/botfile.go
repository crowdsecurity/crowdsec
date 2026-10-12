package exprhelpers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/dnscache"
)

var dataFileBots map[string][]*botEntry

// botEntry is one bot definition (one JSON line in a "bots" data file).
// Matching semantics: (UA && PATH) && (IP || RANGE || RDNS) — the optional
// user_agent and paths regexes are preconditions, then the source must be
// verified by at least one identity check (exact IP, CIDR range, or
// forward-confirmed reverse DNS). UA-only entries are rejected at load time:
// a User-Agent is trivially spoofable.
//
// rdns patterns are regexes matched against the FCrDNS-verified names
// (lowercase, no trailing dot). Anchor them — `(^|\.)googlebot\.com$` —
// or "evilgooglebot.com.attacker.net" matches `googlebot\.com` too.
type botEntry struct {
	Name      string   `json:"name"`
	UserAgent string   `json:"user_agent,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	Ranges    []string `json:"ranges,omitempty"`
	RDNS      []string `json:"rdns,omitempty"`

	// set at load time
	file        string // data file this entry comes from
	uaRegex     *regexp.Regexp
	pathRegexes []*regexp.Regexp
	ipSet       map[netip.Addr]struct{}
	prefixes    []netip.Prefix
	rdnsRegexes []*regexp.Regexp
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

	for _, p := range entry.RDNS {
		// an empty pattern matches every PTR-confirmed host: almost
		// certainly a mistake, reject it
		if p == "" {
			return fmt.Errorf("empty rdns pattern for bot entry '%s' in %s", entry.Name, filename)
		}

		re, err := compileBotRegex(p)
		if err != nil {
			return fmt.Errorf("invalid rdns regex '%s' for bot entry '%s' in %s: %w", p, entry.Name, filename, err)
		}

		entry.rdnsRegexes = append(entry.rdnsRegexes, re)
	}

	entry.file = filename

	dataFileBots[filename] = append(dataFileBots[filename], entry)

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

// BotMatch describes how a request was recognized as a known bot: which entry
// matched, in which data file, and through which identity check. It is what
// makes `cscli appsec-configs match-bot` able to explain a decision.
type BotMatch struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	Method string `json:"method"` // "ip", "range" or "rdns"
	Detail string `json:"detail"` // the address, CIDR or FCrDNS name that matched
}

// MatchKnownBot reports whether the request (source address, User-Agent, path)
// matches a bot definition in any of the named "bots" data files:
// (UA && PATH) && (IP || RANGE || RDNS).
func MatchKnownBot(ip string, ua string, path string, filenames ...string) bool {
	match, err := ExplainKnownBot(ip, ua, path, filenames...)
	if err != nil {
		log.Debugf("MatchKnownBot: %s", err)
		return false
	}

	if match == nil {
		return false
	}

	log.Debugf("MatchKnownBot: %s verified as '%s' via %s (%s)", ip, match.Name, match.Method, match.Detail)

	return true
}

// ExplainKnownBot is MatchKnownBot with the reason attached: it returns the
// matching entry, or nil if the request matches no bot definition.
// The expensive FCrDNS resolution runs at most once per call — after the cheap
// checks across all named files, against every candidate entry at once — and is
// cached per IP.
func ExplainKnownBot(ip string, ua string, path string, filenames ...string) (*BotMatch, error) {
	if len(dataFileBots) == 0 || len(filenames) == 0 {
		return nil, nil
	}

	addr, ok := parseBotAddr(ip)
	if !ok {
		return nil, fmt.Errorf("invalid source address '%s'", ip)
	}

	var rdnsCandidates []*botEntry

	for _, filename := range filenames {
		entries, ok := dataFileBots[filename]
		if !ok {
			log.Debugf("MatchKnownBot: unknown bot data file '%s'", filename)
			continue
		}

		if match := matchBotEntriesByAddr(addr, ua, path, filename, entries, &rdnsCandidates); match != nil {
			return match, nil
		}
	}

	if len(rdnsCandidates) == 0 {
		return nil, nil
	}

	for _, name := range dnscache.ForwardConfirmedNames(addr) {
		for _, entry := range rdnsCandidates {
			if matchAnyRegex(entry.rdnsRegexes, name) {
				return &BotMatch{Name: entry.Name, File: entry.file, Method: "rdns", Detail: name}, nil
			}
		}
	}

	return nil, nil
}

// MatchKnownBotExpr is the expr-registry entrypoint for MatchKnownBot.
// Signature: MatchKnownBot(ip, ua, path string, files ...string) bool.
func MatchKnownBotExpr(params ...any) (any, error) {
	ip, _ := params[0].(string)
	ua, _ := params[1].(string)
	path, _ := params[2].(string)

	filenames := make([]string, 0, len(params)-3)
	for _, p := range params[3:] {
		if s, ok := p.(string); ok {
			filenames = append(filenames, s)
		}
	}

	return MatchKnownBot(ip, ua, path, filenames...), nil
}

// matchBotEntriesByAddr runs the cheap (non-DNS) checks for one file's entries.
// It returns a match on an exact-IP or CIDR-range hit, and collects entries that
// still need FCrDNS verification into rdnsCandidates for the caller to resolve
// once across all files.
func matchBotEntriesByAddr(addr netip.Addr, ua string, path string, filename string, entries []*botEntry, rdnsCandidates *[]*botEntry) *BotMatch {
	for _, entry := range entries {
		if entry.uaRegex != nil && !entry.uaRegex.MatchString(ua) {
			continue
		}

		if len(entry.pathRegexes) > 0 && !matchAnyRegex(entry.pathRegexes, path) {
			continue
		}

		if _, found := entry.ipSet[addr]; found {
			return &BotMatch{Name: entry.Name, File: filename, Method: "ip", Detail: addr.String()}
		}

		for _, prefix := range entry.prefixes {
			if prefix.Contains(addr) {
				return &BotMatch{Name: entry.Name, File: filename, Method: "range", Detail: prefix.String()}
			}
		}

		if len(entry.rdnsRegexes) > 0 {
			*rdnsCandidates = append(*rdnsCandidates, entry)
		}
	}

	return nil
}

func matchAnyRegex(regexes []*regexp.Regexp, s string) bool {
	for _, re := range regexes {
		if re.MatchString(s) {
			return true
		}
	}

	return false
}
