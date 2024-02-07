package exprhelpers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

//	"github.com/sanity-io/litter"
	"github.com/bluele/gcache"
	"github.com/crowdsecurity/crowdsec/pkg/cti"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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

var ctiClient *cti.ClientWithResponses
var ctiLogger *log.Entry

func InitCrowdsecCTI(Key *string, TTL *time.Duration, Size *int, LogLevel *log.Level) error {
	var err error
	if Key == nil || *Key == "" {
		log.Warningf("CTI API key not set or empty, CTI will not be available")
		return cti.ErrDisabled
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
		return fmt.Errorf("while configuring datasource logger: %w", err)
	}
	if LogLevel != nil {
		clog.SetLevel(*LogLevel)
	}
	customLog := log.Fields{
		"type": "crowdsec-cti",
	}
	subLogger := clog.WithFields(customLog)
	ctiLogger = subLogger
	CrowdsecCTIInitCache(*Size, *TTL)
	ctiClient, err = cti.NewClientWithResponses("https://cti.api.crowdsec.net/v2/", cti.WithRequestEditorFn(cti.APIKeyInserter(CTIApiKey)))
	if err != nil {
		return fmt.Errorf("while creating CTI client: %w", err)
	}
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

// func CrowdsecCTI(ip string) (*cti.CTIObject, error) {
func CrowdsecCTI(params ...any) (any, error) {
	var ip string
	if !CTIApiEnabled {
		return &cti.CTIObject{}, cti.ErrDisabled
	}
	var ok bool
	if ip, ok = params[0].(string); !ok {
		return &cti.CTIObject{}, fmt.Errorf("invalid type for ip : %T", params[0])
	}

	if val, err := CTICache.Get(ip); err == nil && val != nil {
		ctiLogger.Debugf("cti cache fetch for %s", ip)
		ret, ok := val.(*cti.CTIObject)
		if !ok {
			ctiLogger.Warningf("CrowdsecCTI: invalid type in cache, removing")
			CTICache.Remove(ip)
		} else {
			return ret, nil
		}
	}

	if !CTIBackOffUntil.IsZero() && time.Now().Before(CTIBackOffUntil) {
		//ctiClient.Logger.Warningf("Crowdsec CTI client is in backoff mode, ending in %s", time.Until(CTIBackOffUntil))
		return &cti.CTIObject{}, cti.ErrLimit
	}

	ctiLogger.Infof("cti call for %s", ip)
	before := time.Now()
	ctx := context.Background() // XXX: timeout?
	ctiResp, err := ctiClient.GetSmokeIpWithResponse(ctx, ip)
	ctiLogger.Debugf("request for %s took %v", ip, time.Since(before))

	if err != nil {
		ctiLogger.Warnf("CTI API error: %s", err)
		return &cti.CTIObject{}, fmt.Errorf("unexpected error: %w", err)
	}

	switch {
	case ctiResp.HTTPResponse != nil && ctiResp.HTTPResponse.StatusCode == 403:
		fmt.Printf("403 error, disabling CTI API\n")
		CTIApiEnabled = false
		ctiLogger.Errorf("Invalid API key provided, disabling CTI API")
		return &cti.CTIObject{}, cti.ErrUnauthorized
	case ctiResp.HTTPResponse != nil && ctiResp.HTTPResponse.StatusCode == 429:
		CTIBackOffUntil = time.Now().Add(CTIBackOffDuration)
		ctiLogger.Errorf("CTI API is throttled, will try again in %s", CTIBackOffDuration)
		return &cti.CTIObject{}, cti.ErrLimit
	case ctiResp.HTTPResponse != nil && ctiResp.HTTPResponse.StatusCode != 200:
		ctiLogger.Warnf("CTI API error: %s", ctiResp.HTTPResponse.Status)
		return &cti.CTIObject{}, fmt.Errorf("unexpected error: %s", ctiResp.HTTPResponse.Status)
	}

	if err := CTICache.SetWithExpire(ip, ctiResp, CacheExpiration); err != nil {
		ctiLogger.Warningf("IpCTI : error while caching CTI : %s", err)
		return &cti.CTIObject{}, cti.ErrUnknown
	}

	ctiLogger.Tracef("CTI response: %s", ctiResp.Body)

	var ctiObject cti.CTIObject
	if err := json.Unmarshal(ctiResp.Body, &ctiObject); err != nil {
		return &cti.CTIObject{}, fmt.Errorf("while unmarshaling CTI response: %w", err)
	}

	return &ctiObject, nil
}
