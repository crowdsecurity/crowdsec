package exprhelpers

import (
	"fmt"
	"time"

	"github.com/bluele/gcache"
	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var CTIUrl = "https://cti.api.crowdsec.net"
var CTIUrlSuffix = "/v2/smoke/"
var CTIApiKey = ""

// this is set for non-recoverable errors, such as 403 when querying API or empty API key
var CTIApiEnabled = false

// when hitting quotas or auth errors, we temporarily disable the API
var CTIBackOffUntil time.Time
var CTIBackOffDuration time.Duration = 5 * time.Minute

var ctiClient *cticlient.CrowdsecCTIClient

func InitCrowdsecCTI(Key *string, TTL *time.Duration, Size *int, LogLevel *log.Level) error {
	if Key == nil || *Key == "" {
		log.Warningf("CTI API key not set or empty, CTI will not be available")
		return cticlient.ErrDisabled
	}
	CTIApiKey = *Key
	if Size == nil {
		Size = new(int)
		*Size = 1000
	}
	if TTL == nil {
		TTL = new(time.Duration)
		*TTL = 5 * time.Minute
	}
	clog := log.New()
	if err := types.ConfigureLogger(clog); err != nil {
		return errors.Wrap(err, "while configuring datasource logger")
	}
	if LogLevel != nil {
		clog.SetLevel(*LogLevel)
	}
	customLog := log.Fields{
		"type": "crowdsec-cti",
	}
	subLogger := clog.WithFields(customLog)
	CrowdsecCTIInitCache(*Size, *TTL)
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
var CTICache gcache.Cache
var CacheExpiration time.Duration

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
		if !ok {
			ctiClient.Logger.Warningf("CrowdsecCTI: invalid type in cache, removing")
			CTICache.Remove(ip)
		} else {
			return ret, nil
		}
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
			return &cticlient.SmokeItem{}, fmt.Errorf("unexpected error : %v", err)
		}
	}

	if err := CTICache.SetWithExpire(ip, ctiResp, CacheExpiration); err != nil {
		ctiClient.Logger.Warningf("IpCTI : error while caching CTI : %s", err)
		return &cticlient.SmokeItem{}, cticlient.ErrUnknown
	}

	ctiClient.Logger.Tracef("CTI response : %v", *ctiResp)

	return ctiResp, nil
}
