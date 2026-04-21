package exprhelpers

import (
	"net"
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
