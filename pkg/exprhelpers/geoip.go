package exprhelpers

import (
	"errors"
	"fmt"
	"net"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/hookreq"
)

func GeoIPEnrich(params ...any) (any, error) {
	if geoIPCityReader == nil {
		return nil, nil
	}

	ip := params[0].(string)

	parsedIP := net.ParseIP(ip)

	city, err := geoIPCityReader.City(parsedIP)
	if err != nil {
		return nil, err
	}

	return city, nil
}

// IPToCountryString resolves an IP address string to its ISO-3166 alpha-2
// country code, returning an empty string on any nil/parse/lookup failure.
// Intended for internal Go callers; expr rules use IPToCountry.
func IPToCountryString(ip string) string {
	if geoIPCityReader == nil || ip == "" {
		return ""
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}

	city, err := geoIPCityReader.City(parsedIP)
	if err != nil || city == nil {
		return ""
	}

	return city.Country.IsoCode
}

// IPToCountry wraps IPToCountryString for expr. Lets rules write
// `IPToCountry(req.RemoteAddr)` instead of
// `GeoIPEnrich(req.RemoteAddr)?.Country.IsoCode` when they only need the
// country and want nil-safety.
func IPToCountry(params ...any) (any, error) {
	ip, _ := params[0].(string)
	return IPToCountryString(ip), nil
}

func GeoIPASNEnrich(params ...any) (any, error) {
	if geoIPASNReader == nil {
		return nil, nil
	}

	ip := params[0].(string)

	parsedIP := net.ParseIP(ip)
	asn, err := geoIPASNReader.ASN(parsedIP)
	if err != nil {
		return nil, err
	}

	return asn, nil
}

func GeoIPRangeEnrich(params ...any) (any, error) {
	if geoIPRangeReader == nil {
		return nil, nil
	}

	ip := params[0].(string)

	var dummy interface{}

	parsedIP := net.ParseIP(ip)
	rangeIP, ok, err := geoIPRangeReader.LookupNetwork(parsedIP, &dummy)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	return rangeIP, nil
}

// LookupHookGeo fills the appsec `req.Geo` fields. It decodes only those fields:
// the full geoip2 records cost ~5x more per request. Fields whose database is
// missing or whose lookup fails stay zero; the returned error is informational.
func LookupHookGeo(ip string) (hookreq.Geo, error) {
	var geo hookreq.Geo

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return geo, nil
	}

	var errs []error

	if geoIPCityRawReader != nil {
		var city struct {
			Country struct {
				IsoCode           string `maxminddb:"iso_code"`
				IsInEuropeanUnion bool   `maxminddb:"is_in_european_union"`
			} `maxminddb:"country"`
		}

		if err := geoIPCityRawReader.Lookup(parsedIP, &city); err != nil {
			errs = append(errs, fmt.Errorf("city lookup: %w", err))
		} else {
			geo.Country = city.Country.IsoCode
			geo.IsInEU = city.Country.IsInEuropeanUnion
		}
	}

	// The range reader is the ASN database: one lookup yields the network and the ASN.
	if geoIPRangeReader != nil {
		var asn struct {
			Number uint   `maxminddb:"autonomous_system_number"`
			Org    string `maxminddb:"autonomous_system_organization"`
		}

		network, ok, err := geoIPRangeReader.LookupNetwork(parsedIP, &asn)

		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("ASN lookup: %w", err))
		case ok:
			geo.ASNumber = asn.Number
			geo.ASOrg = asn.Org
			geo.Range = network.String()
		}
	}

	return geo, errors.Join(errs...)
}
