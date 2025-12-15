package allowlists

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gaissmai/bart"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
)

const allowlistRefreshInterval = 60 * time.Second

// metadata stores Description and AllowlistName for a CIDR prefix
type metadata struct {
	Description   string
	AllowlistName string
}

type AppsecAllowlist struct {
	LAPIClient *apiclient.ApiClient
	trie       *bart.Lite             // BART lite table for IP/CIDR lookups
	meta       map[string]*metadata   // Metadata keyed by CIDR prefix string
	lock       sync.RWMutex
	logger     *log.Entry
	tomb       *tomb.Tomb
}

func NewAppsecAllowlist(logger *log.Entry) *AppsecAllowlist {
	a := &AppsecAllowlist{
		logger: logger.WithField("component", "appsec-allowlist"),
		trie:   new(bart.Lite),
		meta:   make(map[string]*metadata),
	}

	return a
}

func (a *AppsecAllowlist) Start(ctx context.Context, client *apiclient.ApiClient) error {
	a.LAPIClient = client
	err := a.FetchAllowlists(ctx)
	return err
}

func (a *AppsecAllowlist) FetchAllowlists(ctx context.Context) error {
	a.logger.Debug("fetching allowlists")

	allowlists, _, err := a.LAPIClient.Allowlists.List(ctx, apiclient.AllowlistListOpts{WithContent: true})
	if err != nil {
		return err
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	prevSize := a.trie.Size()
	a.trie = new(bart.Lite)
	a.meta = make(map[string]*metadata)

	var ipCount, cidrCount int

	for _, allowlist := range *allowlists {
		for _, item := range allowlist.Items {
			var prefix netip.Prefix
			var err error

			if strings.Contains(item.Value, "/") {
				// It's a CIDR range
				prefix, err = netip.ParsePrefix(item.Value)
				if err != nil {
					continue
				}
				cidrCount++
			} else {
				// It's a single IP - convert to /32 (IPv4) or /128 (IPv6)
				addr, err := netip.ParseAddr(item.Value)
				if err != nil {
					continue
				}
				if addr.Is4() {
					prefix = netip.PrefixFrom(addr, 32)
				} else {
					prefix = netip.PrefixFrom(addr, 128)
				}
				ipCount++
			}

			// Insert into BART lite trie
			a.trie.Insert(prefix)

			// Store metadata keyed by prefix string
			prefixStr := prefix.String()
			a.meta[prefixStr] = &metadata{
				Description:   item.Description,
				AllowlistName: allowlist.Name,
			}
		}
	}

	if a.trie.Size() != prevSize && a.trie.Size() > 0 {
		a.logger.Infof("fetched %d IPs and %d ranges (total: %d entries)", ipCount, cidrCount, a.trie.Size())
	}
	a.logger.Debugf("fetched %d IPs and %d ranges (total: %d entries)", ipCount, cidrCount, a.trie.Size())

	return nil
}

func (a *AppsecAllowlist) updateAllowlists(ctx context.Context) {
	ticker := time.NewTicker(allowlistRefreshInterval)

	for {
		select {
		case <-ticker.C:
			if err := a.FetchAllowlists(ctx); err != nil {
				a.logger.Errorf("failed to fetch allowlists: %s", err)
			}
		case <-a.tomb.Dying():
			ticker.Stop()
			return
		}
	}
}

func (a *AppsecAllowlist) StartRefresh(ctx context.Context, t *tomb.Tomb) {
	a.tomb = t
	a.tomb.Go(func() error {
		a.updateAllowlists(ctx)
		return nil
	})
}

func (a *AppsecAllowlist) IsAllowlisted(sourceIP string) (bool, string) {
	a.lock.RLock()
	defer a.lock.RUnlock()

	ip, err := netip.ParseAddr(sourceIP)
	if err != nil {
		a.logger.Warnf("failed to parse IP %s", sourceIP)
		return false, ""
	}

	// Check if IP is in the trie
	if !a.trie.Contains(ip) {
		return false, ""
	}

	// IP is allowlisted, find the matching prefix to get metadata
	// Use LPM (Longest Prefix Match) to find the most specific matching prefix
	// Create a /32 (IPv4) or /128 (IPv6) prefix from the IP for LPM lookup
	var queryPrefix netip.Prefix
	if ip.Is4() {
		queryPrefix = netip.PrefixFrom(ip, 32)
	} else {
		queryPrefix = netip.PrefixFrom(ip, 128)
	}
	prefix, ok := a.trie.LookupPrefixLPM(queryPrefix)
	if !ok {
		// Should not happen if Contains returned true, but handle gracefully
		a.logger.Debugf("IP %s is allowlisted but no prefix found", sourceIP)
		return true, sourceIP
	}

	// Get metadata for the matching prefix
	prefixStr := prefix.String()
	meta, exists := a.meta[prefixStr]
	if !exists {
		// Metadata not found, return basic reason
		a.logger.Debugf("IP %s is allowlisted by %s", sourceIP, prefixStr)
		return true, prefixStr
	}

	a.logger.Debugf("IP %s is allowlisted by %s from %s", sourceIP, meta.Description, meta.AllowlistName)
	reason := prefixStr + " from " + meta.AllowlistName
	if meta.Description != "" {
		reason += " (" + meta.Description + ")"
	}
	return true, reason
}
