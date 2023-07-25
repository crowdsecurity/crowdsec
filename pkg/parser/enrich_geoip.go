package parser

import (
	"fmt"
	"net"
	"strconv"

	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func IpToRange(field string, p *types.Event, ctx interface{}, plog *log.Entry) (map[string]string, error) {
	var dummy interface{}
	ret := make(map[string]string)

	if field == "" {
		return nil, nil
	}
	ip := net.ParseIP(field)
	if ip == nil {
		plog.Infof("Can't parse ip %s, no range enrich", field)
		return nil, nil
	}
	net, ok, err := ctx.(*maxminddb.Reader).LookupNetwork(ip, &dummy)
	if err != nil {
		plog.Errorf("Failed to fetch network for %s : %v", ip.String(), err)
		return nil, nil
	}
	if !ok {
		plog.Debugf("Unable to find range of %s", ip.String())
		return nil, nil
	}
	ret["SourceRange"] = net.String()
	return ret, nil
}

func GeoIpASN(field string, p *types.Event, ctx interface{}, plog *log.Entry) (map[string]string, error) {
	ret := make(map[string]string)
	if field == "" {
		return nil, nil
	}

	ip := net.ParseIP(field)
	if ip == nil {
		plog.Infof("Can't parse ip %s, no ASN enrich", ip)
		return nil, nil
	}
	record, err := ctx.(*geoip2.Reader).ASN(ip)
	if err != nil {
		plog.Errorf("Unable to enrich ip '%s'", field)
		return nil, nil //nolint:nilerr
	}
	ret["ASNNumber"] = fmt.Sprintf("%d", record.AutonomousSystemNumber)
	ret["ASNumber"] = fmt.Sprintf("%d", record.AutonomousSystemNumber)
	ret["ASNOrg"] = record.AutonomousSystemOrganization

	plog.Tracef("geoip ASN %s -> %s, %s", field, ret["ASNNumber"], ret["ASNOrg"])

	return ret, nil
}

func GeoIpCity(field string, p *types.Event, ctx interface{}, plog *log.Entry) (map[string]string, error) {
	ret := make(map[string]string)
	if field == "" {
		return nil, nil
	}
	ip := net.ParseIP(field)
	if ip == nil {
		plog.Infof("Can't parse ip %s, no City enrich", ip)
		return nil, nil
	}
	record, err := ctx.(*geoip2.Reader).City(ip)
	if err != nil {
		plog.Debugf("Unable to enrich ip '%s'", ip)
		return nil, nil //nolint:nilerr
	}
	if record.Country.IsoCode != "" {
		ret["IsoCode"] = record.Country.IsoCode
		ret["IsInEU"] = strconv.FormatBool(record.Country.IsInEuropeanUnion)
	} else if record.RegisteredCountry.IsoCode != "" {
		ret["IsoCode"] = record.RegisteredCountry.IsoCode
		ret["IsInEU"] = strconv.FormatBool(record.RegisteredCountry.IsInEuropeanUnion)
	} else if record.RepresentedCountry.IsoCode != "" {
		ret["IsoCode"] = record.RepresentedCountry.IsoCode
		ret["IsInEU"] = strconv.FormatBool(record.RepresentedCountry.IsInEuropeanUnion)
	} else {
		ret["IsoCode"] = ""
		ret["IsInEU"] = strconv.FormatBool(false)
	}

	ret["Latitude"] = fmt.Sprintf("%f", record.Location.Latitude)
	ret["Longitude"] = fmt.Sprintf("%f", record.Location.Longitude)

	plog.Tracef("geoip City %s -> %s, %s", field, ret["IsoCode"], ret["IsInEU"])

	return ret, nil
}

func GeoIPCityInit(cfg map[string]string) (interface{}, error) {
	dbCityReader, err := geoip2.Open(cfg["datadir"] + "/GeoLite2-City.mmdb")
	if err != nil {
		log.Debugf("couldn't open geoip : %v", err)
		return nil, err
	}

	return dbCityReader, nil
}

func GeoIPASNInit(cfg map[string]string) (interface{}, error) {
	dbASReader, err := geoip2.Open(cfg["datadir"] + "/GeoLite2-ASN.mmdb")
	if err != nil {
		log.Debugf("couldn't open geoip : %v", err)
		return nil, err
	}

	return dbASReader, nil
}

func IpToRangeInit(cfg map[string]string) (interface{}, error) {
	ipToRangeReader, err := maxminddb.Open(cfg["datadir"] + "/GeoLite2-ASN.mmdb")
	if err != nil {
		log.Debugf("couldn't open geoip : %v", err)
		return nil, err
	}

	return ipToRangeReader, nil
}
