package parser

import (
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

/* should be part of a package shared with enrich/geoip.go */
type (
	EnrichFunc func(string, *types.Event, *log.Entry) (map[string]string, error)
	InitFunc   func(map[string]string) (interface{}, error)
)

type EnricherCtx struct {
	Registered map[string]*Enricher
}

type Enricher struct {
	Name       string
	EnrichFunc EnrichFunc
}

/* mimic plugin loading */
func Loadplugin() (EnricherCtx, error) {
	enricherCtx := EnricherCtx{}
	enricherCtx.Registered = make(map[string]*Enricher)

	EnrichersList := []*Enricher{
		{
			Name:       "GeoIpCity",
			EnrichFunc: GeoIpCity,
		},
		{
			Name:       "GeoIpASN",
			EnrichFunc: GeoIpASN,
		},
		{
			Name:       "IpToRange",
			EnrichFunc: IpToRange,
		},
		{
			Name:       "reverse_dns",
			EnrichFunc: reverse_dns,
		},
		{
			Name:       "ParseDate",
			EnrichFunc: ParseDate,
		},
		{
			Name:       "UnmarshalJSON",
			EnrichFunc: unmarshalJSON,
		},
	}

	for _, enricher := range EnrichersList {
		log.Infof("Successfully registered enricher '%s'", enricher.Name)
		enricherCtx.Registered[enricher.Name] = enricher
	}

	return enricherCtx, nil
}
