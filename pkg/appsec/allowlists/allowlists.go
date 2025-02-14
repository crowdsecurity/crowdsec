package allowlists

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
)

const allowlistRefreshInterval = 60 * time.Second

type AppsecAllowlist struct {
	LAPIClient *apiclient.ApiClient
	ips        []net.IP
	ranges     []net.IPNet
	lock       sync.RWMutex
	logger     *log.Entry
	tomb       *tomb.Tomb
}

func NewAppsecAllowlist(client *apiclient.ApiClient, logger *log.Entry) *AppsecAllowlist {
	a := &AppsecAllowlist{
		LAPIClient: client,
		logger:     logger.WithField("component", "appsec-allowlist"),
		ips:        []net.IP{},
		ranges:     []net.IPNet{},
	}

	if err := a.fetchAllowlists(); err != nil {
		a.logger.Errorf("failed to fetch allowlists: %s", err)
	}

	return a
}

func (a *AppsecAllowlist) fetchAllowlists() error {
	a.logger.Debug("fetching allowlists")
	allowlists, _, err := a.LAPIClient.Allowlists.List(context.TODO(), apiclient.AllowlistListOpts{WithContent: true})
	if err != nil {
		return err
	}

	a.lock.Lock()
	defer a.lock.Unlock()
	a.ranges = []net.IPNet{}
	a.ips = []net.IP{}
	for _, allowlist := range *allowlists {
		for _, item := range allowlist.Items {
			if strings.Contains(item.Value, "/") {
				_, ipNet, err := net.ParseCIDR(item.Value)
				if err != nil {
					continue
				}
				a.ranges = append(a.ranges, *ipNet)
			} else {
				ip := net.ParseIP(item.Value)
				if ip == nil {
					return nil
				}
				a.ips = append(a.ips, ip)
			}
		}
	}
	a.logger.Debugf("fetched %d IPs and %d ranges", len(a.ips), len(a.ranges))
	a.logger.Tracef("allowlisted ips: %+v", a.ips)
	a.logger.Tracef("allowlisted ranges: %+v", a.ranges)
	return nil
}

func (a *AppsecAllowlist) updateAllowlists() error {
	ticker := time.NewTicker(allowlistRefreshInterval)

	for {
		select {
		case <-ticker.C:
			if err := a.fetchAllowlists(); err != nil {
				a.logger.Errorf("failed to fetch allowlists: %s", err)
			}
		case <-a.tomb.Dying():
			ticker.Stop()
			return nil
		}
	}
}

func (a *AppsecAllowlist) StartRefresh(t *tomb.Tomb) {
	a.tomb = t
	a.tomb.Go(a.updateAllowlists)
}

func (a *AppsecAllowlist) IsAllowlisted(sourceIP string) bool {
	a.lock.RLock()
	defer a.lock.RUnlock()

	ip := net.ParseIP(sourceIP)
	if ip == nil {
		a.logger.Warnf("failed to parse IP %s", sourceIP)
		return false
	}

	for _, allowedIP := range a.ips {
		if allowedIP.Equal(ip) {
			a.logger.Debugf("IP %s is allowlisted", sourceIP)
			return true
		}
	}

	for _, allowedRange := range a.ranges {
		if allowedRange.Contains(ip) {
			a.logger.Debugf("IP %s is within allowlisted range", sourceIP)
			return true
		}
	}

	return false
}
