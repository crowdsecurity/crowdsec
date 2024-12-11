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
