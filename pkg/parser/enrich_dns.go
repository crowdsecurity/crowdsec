package parser

import (
	"net/netip"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/dnscache"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

/* All plugins must export a list of function pointers for exported symbols */
//var ExportedFuncs = []string{"reverse_dns"}

func reverse_dns(field string, p *pipeline.Event, plog *log.Entry) (map[string]string, error) {
	if field == "" {
		return nil, nil
	}

	addr, err := netip.ParseAddr(field)
	if err != nil {
		plog.Debugf("invalid address '%s'", field)
		return nil, nil //nolint:nilerr // a non-resolvable field is not an enrichment error
	}

	rets := dnscache.PTRRecords(addr)
	if len(rets) == 0 {
		plog.Debugf("failed to resolve '%s'", field)
		return nil, nil
	}

	return map[string]string{"reverse_dns": rets[0]}, nil
}
