package exprhelpers

import (
	"net"
	"net/netip"
)

// This struct is lifted from geoip2-golang to avoid dependency and have better control over the names of the fields.
type GeoIPCity struct {
	City struct {
		Names     map[string]string `maxminddb:"names"`
		GeoNameID uint              `maxminddb:"geoname_id"`
	} `maxminddb:"city"`
	Postal struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"postal"`
	Continent struct {
		Names     map[string]string `maxminddb:"names"`
		Code      string            `maxminddb:"code"`
		GeoNameID uint              `maxminddb:"geoname_id"`
	} `maxminddb:"continent"`
	Subdivisions []struct {
		Names     map[string]string `maxminddb:"names"`
		IsoCode   string            `maxminddb:"iso_code"`
		GeoNameID uint              `maxminddb:"geoname_id"`
	} `maxminddb:"subdivisions"`
	RepresentedCountry struct {
		Names             map[string]string `maxminddb:"names"`
		IsoCode           string            `maxminddb:"iso_code"`
		Type              string            `maxminddb:"type"`
		GeoNameID         uint              `maxminddb:"geoname_id"`
		IsInEuropeanUnion bool              `maxminddb:"is_in_european_union"`
	} `maxminddb:"represented_country"`
	Country struct {
		Names             map[string]string `maxminddb:"names"`
		IsoCode           string            `maxminddb:"iso_code"`
		GeoNameID         uint              `maxminddb:"geoname_id"`
		IsInEuropeanUnion bool              `maxminddb:"is_in_european_union"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		Names             map[string]string `maxminddb:"names"`
		IsoCode           string            `maxminddb:"iso_code"`
		GeoNameID         uint              `maxminddb:"geoname_id"`
		IsInEuropeanUnion bool              `maxminddb:"is_in_european_union"`
	} `maxminddb:"registered_country"`
	Location struct {
		TimeZone       string  `maxminddb:"time_zone"`
		Latitude       float64 `maxminddb:"latitude"`
		Longitude      float64 `maxminddb:"longitude"`
		MetroCode      uint    `maxminddb:"metro_code"`
		AccuracyRadius uint16  `maxminddb:"accuracy_radius"`
	} `maxminddb:"location"`
	Traits struct {
		IsAnonymousProxy    bool `maxminddb:"is_anonymous_proxy"`
		IsAnycast           bool `maxminddb:"is_anycast"`
		IsSatelliteProvider bool `maxminddb:"is_satellite_provider"`
	} `maxminddb:"traits"`
}

type GeoIPASN struct {
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
}

func GeoIPEnrich(params ...any) (any, error) {
	if geoIPCityReader == nil {
		return nil, nil
	}

	ip := params[0].(string)

	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, err
	}

	city := &GeoIPCity{}

	err = geoIPCityReader.Lookup(parsedIP).Decode(city)
	if err != nil {
		return nil, err
	}

	return city, nil
}

func GeoIPASNEnrich(params ...any) (any, error) {
	if geoIPASNRangeReader == nil {
		return nil, nil
	}

	ip := params[0].(string)

	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, err
	}

	asn := &GeoIPASN{}

	err = geoIPASNRangeReader.Lookup(parsedIP).Decode(asn)
	if err != nil {
		return nil, err
	}

	return asn, nil
}

func GeoIPRangeEnrich(params ...any) (any, error) {
	if geoIPASNRangeReader == nil {
		return nil, nil
	}

	ip := params[0].(string)

	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, err
	}

	// We need to convert back to net.IPNet for backwards compatibility
	prefix := geoIPASNRangeReader.Lookup(parsedIP).Prefix().Masked()
	addr := prefix.Addr()
	bits, totalBits := prefix.Bits(), addr.BitLen()

	rangeIP := &net.IPNet{
		IP:   addr.AsSlice(),
		Mask: net.CIDRMask(bits, totalBits),
	}

	return rangeIP, nil
}
