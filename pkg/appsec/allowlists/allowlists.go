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

type rangeAllowlist struct {
	Range         net.IPNet
	Description   string
	AllowlistName string
}

type ipAllowlist struct {
	IP            net.IP
	Description   string
	AllowlistName string
}

type AppsecAllowlist struct {
	LAPIClient *apiclient.ApiClient
	ips        []ipAllowlist
	ranges     []rangeAllowlist
	lock       sync.RWMutex
	logger     *log.Entry
	tomb       *tomb.Tomb
}

func NewAppsecAllowlist(client *apiclient.ApiClient, logger *log.Entry) *AppsecAllowlist {
	a := &AppsecAllowlist{
		LAPIClient: client,
		logger:     logger.WithField("component", "appsec-allowlist"),
		ips:        []ipAllowlist{},
		ranges:     []rangeAllowlist{},
	}

	if err := a.FetchAllowlists(); err != nil {
		a.logger.Errorf("failed to fetch allowlists: %s", err)
	}

	return a
}

func (a *AppsecAllowlist) FetchAllowlists() error {
	a.logger.Debug("fetching allowlists")

	allowlists, _, err := a.LAPIClient.Allowlists.List(context.TODO(), apiclient.AllowlistListOpts{WithContent: true})
	if err != nil {
		return err
	}

	a.lock.Lock()
	defer a.lock.Unlock()
	a.ranges = []rangeAllowlist{}
	a.ips = []ipAllowlist{}

	for _, allowlist := range *allowlists {
		for _, item := range allowlist.Items {
			if strings.Contains(item.Value, "/") {
				_, ipNet, err := net.ParseCIDR(item.Value)
				if err != nil {
					continue
				}

				a.ranges = append(a.ranges, rangeAllowlist{
					Range:         *ipNet,
					Description:   item.Description,
					AllowlistName: allowlist.Name,
				})
			} else {
				ip := net.ParseIP(item.Value)
				if ip == nil {
					return nil
				}

				a.ips = append(a.ips, ipAllowlist{
					IP:            ip,
					Description:   item.Description,
					AllowlistName: allowlist.Name,
				})
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
			if err := a.FetchAllowlists(); err != nil {
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

func (a *AppsecAllowlist) IsAllowlisted(sourceIP string) (bool, string) {
	a.lock.RLock()
	defer a.lock.RUnlock()

	ip := net.ParseIP(sourceIP)
	if ip == nil {
		a.logger.Warnf("failed to parse IP %s", sourceIP)
		return false, ""
	}

	for _, allowedIP := range a.ips {
		if allowedIP.IP.Equal(ip) {
			a.logger.Debugf("IP %s is allowlisted by %s from %s", sourceIP, allowedIP.Description, allowedIP.AllowlistName)
			reason := allowedIP.IP.String() + " from " + allowedIP.AllowlistName
			if allowedIP.Description != "" {
				reason += " (" + allowedIP.Description + ")"
			}
			return true, reason
		}
	}

	for _, allowedRange := range a.ranges {
		if allowedRange.Range.Contains(ip) {
			a.logger.Debugf("IP %s is within allowlisted range by %s from %s", sourceIP, allowedRange.Description, allowedRange.AllowlistName)
			reason := allowedRange.Range.String() + " from " + allowedRange.AllowlistName
			if allowedRange.Description != "" {
				reason += " (" + allowedRange.Description + ")"
			}
			return true, reason
		}
	}

	return false, ""
}
