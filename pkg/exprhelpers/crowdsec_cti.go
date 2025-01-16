package exprhelpers

import (
	"errors"
	"fmt"
	"time"

	"github.com/bluele/gcache"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var (
	CTIUrl       = "https://cti.api.crowdsec.net"
	CTIUrlSuffix = "/v2/smoke/"
	CTIApiKey    = ""
)

// this is set for non-recoverable errors, such as 403 when querying API or empty API key
var CTIApiEnabled = false

// when hitting quotas or auth errors, we temporarily disable the API
var (
	CTIBackOffUntil    time.Time
	CTIBackOffDuration = 5 * time.Minute
)

var ctiClient *cticlient.CrowdsecCTIClient

func InitCrowdsecCTI(key *string, ttl *time.Duration, size *int, logLevel *log.Level) error {
	if key == nil || *key == "" {
		log.Warningf("CTI API key not set or empty, CTI will not be available")
		return cticlient.ErrDisabled
	}
	CTIApiKey = *key
	if size == nil {
		size = new(int)
		*size = 1000
	}
	if ttl == nil {
		ttl = new(time.Duration)
		*ttl = 5 * time.Minute
	}
	clog := log.New()
	if err := types.ConfigureLogger(clog); err != nil {
		return fmt.Errorf("while configuring datasource logger: %w", err)
	}
	if logLevel != nil {
		clog.SetLevel(*logLevel)
	}
	subLogger := clog.WithField("type", "crowdsec-cti")
	CrowdsecCTIInitCache(*size, *ttl)
	ctiClient = cticlient.NewCrowdsecCTIClient(cticlient.WithAPIKey(CTIApiKey), cticlient.WithLogger(subLogger))
	CTIApiEnabled = true
	return nil
}

func ShutdownCrowdsecCTI() {
	if CTICache != nil {
		CTICache.Purge()
	}
	CTIApiKey = ""
	CTIApiEnabled = false
}

// Cache for responses
var (
	CTICache        gcache.Cache
	CacheExpiration time.Duration
)

func CrowdsecCTIInitCache(size int, ttl time.Duration) {
	CTICache = gcache.New(size).LRU().Build()
	CacheExpiration = ttl
}

// func CrowdsecCTI(ip string) (*cticlient.SmokeItem, error) {
func CrowdsecCTI(params ...any) (any, error) {
	var ip string
	if !CTIApiEnabled {
		return &cticlient.SmokeItem{}, cticlient.ErrDisabled
	}
	var ok bool
	if ip, ok = params[0].(string); !ok {
		return &cticlient.SmokeItem{}, fmt.Errorf("invalid type for ip : %T", params[0])
	}

	if val, err := CTICache.Get(ip); err == nil && val != nil {
		ctiClient.Logger.Debugf("cti cache fetch for %s", ip)
		ret, ok := val.(*cticlient.SmokeItem)
		if ok {
			return ret, nil
		}
		ctiClient.Logger.Warningf("CrowdsecCTI: invalid type in cache, removing")
		CTICache.Remove(ip)
	}

	if !CTIBackOffUntil.IsZero() && time.Now().Before(CTIBackOffUntil) {
		//ctiClient.Logger.Warningf("Crowdsec CTI client is in backoff mode, ending in %s", time.Until(CTIBackOffUntil))
		return &cticlient.SmokeItem{}, cticlient.ErrLimit
	}

	ctiClient.Logger.Infof("cti call for %s", ip)
	before := time.Now()
	ctiResp, err := ctiClient.GetIPInfo(ip)
	ctiClient.Logger.Debugf("request for %s took %v", ip, time.Since(before))
	if err != nil {
		switch {
		case errors.Is(err, cticlient.ErrUnauthorized):
			CTIApiEnabled = false
			ctiClient.Logger.Errorf("Invalid API key provided, disabling CTI API")
			return &cticlient.SmokeItem{}, cticlient.ErrUnauthorized
		case errors.Is(err, cticlient.ErrLimit):
			CTIBackOffUntil = time.Now().Add(CTIBackOffDuration)
			ctiClient.Logger.Errorf("CTI API is throttled, will try again in %s", CTIBackOffDuration)
			return &cticlient.SmokeItem{}, cticlient.ErrLimit
		default:
			ctiClient.Logger.Warnf("CTI API error : %s", err)
			return &cticlient.SmokeItem{}, fmt.Errorf("unexpected error: %w", err)
		}
	}

	if err := CTICache.SetWithExpire(ip, ctiResp, CacheExpiration); err != nil {
		ctiClient.Logger.Warningf("IpCTI : error while caching CTI : %s", err)
		return &cticlient.SmokeItem{}, cticlient.ErrUnknown
	}

	ctiClient.Logger.Tracef("CTI response : %v", *ctiResp)

	return ctiResp, nil
}
