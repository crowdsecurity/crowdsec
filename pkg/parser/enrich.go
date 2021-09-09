package parser

import (
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

/* should be part of a packaged shared with enrich/geoip.go */
type EnrichFunc func(string, *types.Event, interface{}) (map[string]string, error)
type InitFunc func(map[string]string) (interface{}, error)

type EnricherCtx struct {
	Registered map[string]*Enricher
}

type Enricher struct {
	Name       string
	InitFunc   InitFunc
	EnrichFunc EnrichFunc
	Ctx        interface{}
}

/* mimic plugin loading */
func Loadplugin(path string) (EnricherCtx, error) {
	enricherCtx := EnricherCtx{}
	enricherCtx.Registered = make(map[string]*Enricher)

	enricherConfig := map[string]string{"datadir": path}

	EnrichersList := []*Enricher{
		{
			Name:       "GeoIpCity",
			InitFunc:   GeoIPCityInit,
			EnrichFunc: GeoIpCity,
		},
		{
			Name:       "GeoIpASN",
			InitFunc:   GeoIPASNInit,
			EnrichFunc: GeoIpASN,
		},
		{
			Name:       "IpToRange",
			InitFunc:   IpToRangeInit,
			EnrichFunc: IpToRange,
		},
		{
			Name:       "reverse_dns",
			InitFunc:   reverseDNSInit,
			EnrichFunc: reverse_dns,
		},
		{
			Name:       "ParseDate",
			InitFunc:   parseDateInit,
			EnrichFunc: ParseDate,
		},
	}

	for _, enricher := range EnrichersList {
		log.Debugf("Initiating enricher '%s'", enricher.Name)
		pluginCtx, err := enricher.InitFunc(enricherConfig)
		if err != nil {
			log.Errorf("unable to register plugin '%s': %v", enricher.Name, err)
			continue
		}
		enricher.Ctx = pluginCtx
		log.Infof("Successfully registered enricher '%s'", enricher.Name)
		enricherCtx.Registered[enricher.Name] = enricher
	}

	return enricherCtx, nil
}
