package parser

import (
	"net"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	//"github.com/crowdsecurity/crowdsec/pkg/parser"
)

/* All plugins must export a list of function pointers for exported symbols */
//var ExportedFuncs = []string{"reverse_dns"}

func reverse_dns(field string, p *types.Event, ctx interface{}, plog *log.Entry) (map[string]string, error) {
	ret := make(map[string]string)
	if field == "" {
		return nil, nil
	}
	rets, err := net.LookupAddr(field)
	if err != nil {
		plog.Debugf("failed to resolve '%s'", field)
		return nil, nil //nolint:nilerr
	}
	//When using the host C library resolver, at most one result will be returned. To bypass the host resolver, use a custom Resolver.
	ret["reverse_dns"] = rets[0]
	return ret, nil
}

func reverseDNSInit(cfg map[string]string) (interface{}, error) {
	return nil, nil
}
