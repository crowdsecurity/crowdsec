package exprhelpers

import (
	"fmt"
	"time"

	"github.com/bluele/gcache"
	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
	log "github.com/sirupsen/logrus"
)

var CTIUrl = "https://cti.api.dev.crowdsec.net"
var CTIUrlSuffix = "/v2/smoke/"
var CTIApiKey = ""

// this is set for non-recoverable errors, such as 403 when querying API or empty API key
var CTIApiEnabled = true

// when hitting quotas or auth errors, we temporarily disable the API
var CTIBackOffUntil time.Time
var CTIBackOffDuration time.Duration = 5 * time.Minute

var ctiClient *cticlient.CrowdsecCTIClient

func InitCrowdsecCTI(Key *string, TTL *time.Duration, Size *int) error {
	if Key != nil {
		CTIApiKey = *Key
	} else {
		CTIApiEnabled = false
		return fmt.Errorf("CTI API key not set, CTI will not be available")
	}
	if Size == nil {
		Size = new(int)
		*Size = 1000
	}
	if TTL == nil {
		TTL = new(time.Duration)
		*TTL = 5 * time.Minute
	}

	CrowdsecCTIInitCache(*Size, *TTL)
	log.Warningf("heree wee gooooo")
	ctiClient = cticlient.NewCrowdsecCTIClient(cticlient.WithAPIKey(CTIApiKey))
	return nil
}

func ShutdownCrowdsecCTI() {
	if CTICache != nil {
		CTICache.Purge()
	}
	CTIApiKey = ""
	CTIApiEnabled = true
}

// Cache for responses
var CTICache gcache.Cache
var CacheExpiration time.Duration

func CrowdsecCTIInitCache(size int, ttl time.Duration) {
	CTICache = gcache.New(size).LRU().Build()
	CacheExpiration = ttl
}

func CrowdsecCTI(ip string) *cticlient.SmokeItem {
	log.Warningf("cti call for %s", ip)
	if !CTIApiEnabled {
		log.Warningf("Crowdsec CTI API is disabled, please check your configuration")
		return &cticlient.SmokeItem{}
	}

	if CTIApiKey == "" {
		log.Warningf("CrowdsecCTI : no key provided, skipping")
		return &cticlient.SmokeItem{}
	}

	if ctiClient == nil {
		log.Warningf("CrowdsecCTI: no client, skipping")
		return &cticlient.SmokeItem{}
	}

	if val, err := CTICache.Get(ip); err == nil && val != nil {
		ret, ok := val.(*cticlient.SmokeItem)
		if !ok {
			log.Warningf("CrowdsecCTI: invalid type in cache, removing")
			CTICache.Remove(ip)
		} else {
			return ret
		}
	}

	if !CTIBackOffUntil.IsZero() && time.Now().Before(CTIBackOffUntil) {
		log.Warningf("Crowdsec CTI client is in backoff mode, ending in %s", time.Until(CTIBackOffUntil))
		return &cticlient.SmokeItem{}
	}

	ctiResp, err := ctiClient.GetIPInfo(ip)
	if err != nil {
		if err == cticlient.ErrUnauthorized {
			CTIApiEnabled = false
			log.Errorf("Invalid API key provided, disabling CTI API")
		} else if err == cticlient.ErrLimit {
			CTIBackOffUntil = time.Now().Add(CTIBackOffDuration)
			log.Errorf("CTI API is throttled, will try again in %s", CTIBackOffDuration)
		} else {
			log.Warnf("CTI API error : %s", err)
		}
		return &cticlient.SmokeItem{}
	}

	if err := CTICache.SetWithExpire(ip, ctiResp, CacheExpiration); err != nil {
		log.Warningf("IpCTI : error while caching CTI : %s", err)
		return &cticlient.SmokeItem{}
	}

	log.Infof("CTI response : %v", *ctiResp)

	return ctiResp
}
