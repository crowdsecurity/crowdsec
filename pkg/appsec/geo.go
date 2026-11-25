package appsec

import (
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/hookreq"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

// lookupGeo never fails: a missing database, bad IP or failed lookup leaves the matching fields zero.
func lookupGeo(ip string, logger *log.Entry) hookreq.Geo {
	geo, err := exprhelpers.LookupHookGeo(ip)
	if err != nil {
		logger.Debugf("geoip lookup for %s: %s", ip, err)
	}

	return geo
}
