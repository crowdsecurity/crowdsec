package parser

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

/* should be part of a packaged shared with enrich/geoip.go */
type EnrichFunc func(string, *types.Event, interface{}) (map[string]string, error)
type InitFunc func(map[string]string) (interface{}, error)

type EnricherCtx struct {
	Funcs      map[string]EnrichFunc
	Init       InitFunc
	Name       string
	Path       string      //path to .so ?
	RuntimeCtx interface{} //the internal context of plugin, given back over every call
	initiated  bool
}

/* mimic plugin loading */
func Loadplugin(path string) ([]EnricherCtx, error) {
	var err error

	c := EnricherCtx{}
	c.Name = path
	c.Path = path
	/* we don't want to deal with plugin loading for now :p */
	c.Funcs = map[string]EnrichFunc{
		"GeoIpASN":    GeoIpASN,
		"GeoIpCity":   GeoIpCity,
		"reverse_dns": reverse_dns,
		"ParseDate":   ParseDate,
		"IpToRange":   IpToRange,
	}
	c.Init = GeoIpInit

	c.RuntimeCtx, err = c.Init(map[string]string{"datadir": path})
	if err != nil {
		log.Warningf("load (fake) plugin load : %v", err)
		c.initiated = false
	}
	c.initiated = true
	return []EnricherCtx{c}, nil
}

func GenDateParse(date string) (string, time.Time) {
	var (
		layouts = [...]string{
			time.RFC3339,
			"02/Jan/2006:15:04:05 -0700",
			"Mon Jan 2 15:04:05 2006",
			"02-Jan-2006 15:04:05 europe/paris",
			"01/02/2006 15:04:05",
			"2006-01-02 15:04:05.999999999 -0700 MST",
			"Jan  2 15:04:05",
			"Mon Jan 02 15:04:05.000000 2006",
			"2006-01-02T15:04:05Z07:00",
			"2006/01/02",
			"2006/01/02 15:04",
			"2006-01-02",
			"2006-01-02 15:04",
			"2006/01/02 15:04:05",
			"2006-01-02 15:04:05",
		}
	)

	for _, dateFormat := range layouts {
		t, err := time.Parse(dateFormat, date)
		if err == nil && !t.IsZero() {
			//if the year isn't set, set it to current date :)
			if t.Year() == 0 {
				t = t.AddDate(time.Now().Year(), 0, 0)
			}
			retstr, err := t.MarshalText()
			if err != nil {
				log.Warningf("Failed marshaling '%v'", t)
				continue
			}
			return string(retstr), t
		}
	}

	now := time.Now()
	retstr, err := now.MarshalText()
	if err != nil {
		log.Warningf("Failed marshaling current time")
		return "", time.Time{}
	}
	return string(retstr), now
}

func ParseDate(in string, p *types.Event, x interface{}) (map[string]string, error) {

	var ret map[string]string = make(map[string]string)
	tstr, tbin := GenDateParse(in)
	if !tbin.IsZero() {
		ret["MarshaledTime"] = string(tstr)
		return ret, nil
	}

	return nil, nil
}
