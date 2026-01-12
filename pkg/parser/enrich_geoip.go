package parser

import (
	"fmt"
	"net"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func IpToRange(field string, _ *pipeline.Event, plog *log.Entry) (map[string]string, error) {
	if field == "" {
		return nil, nil
	}

	r, err := exprhelpers.GeoIPRangeEnrich(field)
	if err != nil {
		plog.Errorf("Unable to enrich ip '%s'", field)
		return nil, nil //nolint:nilerr
	}

	if r == nil {
		plog.Debugf("No range found for ip '%s'", field)
		return nil, nil
	}

	record, ok := r.(*net.IPNet)

	if !ok {
		return nil, nil
	}

	ret := make(map[string]string)
	ret["SourceRange"] = record.String()

	return ret, nil
}

func GeoIpASN(field string, _ *pipeline.Event, plog *log.Entry) (map[string]string, error) {
	if field == "" {
		return nil, nil
	}

	r, err := exprhelpers.GeoIPASNEnrich(field)
	if err != nil {
		plog.Debugf("Unable to enrich ip '%s'", field)
		return nil, nil //nolint:nilerr
	}

	if r == nil {
		plog.Debugf("No ASN found for ip '%s'", field)
		return nil, nil
	}

	record, ok := r.(*exprhelpers.GeoIPASN)

	if !ok {
		return nil, nil
	}

	ret := make(map[string]string)

	// narrator: it was actually 16 bits
	asnStr := strconv.FormatUint(uint64(record.AutonomousSystemNumber), 10)

	ret["ASNNumber"] = asnStr
	ret["ASNumber"] = asnStr // back-compat
	ret["ASNOrg"] = record.AutonomousSystemOrganization

	plog.Tracef("geoip ASN %s -> %s, %s", field, ret["ASNNumber"], ret["ASNOrg"])

	return ret, nil
}

func GeoIpCity(field string, _ *pipeline.Event, plog *log.Entry) (map[string]string, error) {
	if field == "" {
		return nil, nil
	}

	r, err := exprhelpers.GeoIPEnrich(field)
	if err != nil {
		plog.Debugf("Unable to enrich ip '%s'", field)
		return nil, nil //nolint:nilerr
	}

	if r == nil {
		plog.Debugf("No city found for ip '%s'", field)
		return nil, nil
	}

	record, ok := r.(*exprhelpers.GeoIPCity)

	if !ok {
		return nil, nil
	}

	ret := make(map[string]string)

	switch {
	case record.Country.IsoCode != "":
		ret["IsoCode"] = record.Country.IsoCode
		ret["IsInEU"] = strconv.FormatBool(record.Country.IsInEuropeanUnion)
	case record.RegisteredCountry.IsoCode != "":
		ret["IsoCode"] = record.RegisteredCountry.IsoCode
		ret["IsInEU"] = strconv.FormatBool(record.RegisteredCountry.IsInEuropeanUnion)
	case record.RepresentedCountry.IsoCode != "":
		ret["IsoCode"] = record.RepresentedCountry.IsoCode
		ret["IsInEU"] = strconv.FormatBool(record.RepresentedCountry.IsInEuropeanUnion)
	default:
		ret["IsoCode"] = ""
		ret["IsInEU"] = "false"
	}

	ret["Latitude"] = fmt.Sprintf("%f", record.Location.Latitude)
	ret["Longitude"] = fmt.Sprintf("%f", record.Location.Longitude)

	plog.Tracef("geoip City %s -> %s, %s", field, ret["IsoCode"], ret["IsInEU"])

	return ret, nil
}
