package iplib

import (
	"net"
	"strings"
)

// Net describes an iplib.Net object, the enumerated functions are those that
// are required for comparison, sorting, generic initialization and for
// ancillary functions such as those found in the iid and iana submodules
type Net interface {
	Contains(ip net.IP) bool
	ContainsNet(network Net) bool
	FirstAddress() net.IP
	IP() net.IP
	LastAddress() net.IP
	Mask() net.IPMask
	String() string
	Version() int
}

// NewNet returns a new Net object containing ip at the specified masklen. In
// the Net6 case the hostbits value will be set to 0. If the masklen is set
// to an insane value (greater than 32 for IPv4 or 128 for IPv6) an empty Net
// will be returned
func NewNet(ip net.IP, masklen int) Net {
	if EffectiveVersion(ip) == 6 {
		return NewNet6(ip, masklen, 0)
	}
	return NewNet4(ip, masklen)
}

// NewNetBetween takes two net.IP's as input and will return the largest
// netblock that can fit between them (exclusive of the IP's themselves).
// If there is an exact fit it will set a boolean to true, otherwise the bool
// will be false. If no fit can be found (probably because a >= b) an
// ErrNoValidRange will be returned.
func NewNetBetween(a, b net.IP) (Net, bool, error) {
	if CompareIPs(a, b) != -1 {
		return nil, false, ErrNoValidRange
	}

	if EffectiveVersion(a) != EffectiveVersion(b) {
		return nil, false, ErrNoValidRange
	}

	return fitNetworkBetween(NextIP(a), PreviousIP(b), 1)
}

// ByNet implements sort.Interface for iplib.Net based on the
// starting address of the netblock, with the netmask as a tie breaker. So if
// two Networks are submitted and one is a subset of the other, the enclosing
// network will be returned first.
type ByNet []Net

// Len implements sort.interface Len(), returning the length of the
// ByNetwork array
func (bn ByNet) Len() int {
	return len(bn)
}

// Swap implements sort.interface Swap(), swapping two elements in our array
func (bn ByNet) Swap(a, b int) {
	bn[a], bn[b] = bn[b], bn[a]
}

// Less implements sort.interface Less(), given two elements in the array it
// returns true if the LHS should sort before the RHS. For details on the
// implementation, see CompareNets()
func (bn ByNet) Less(a, b int) bool {
	val := CompareNets(bn[a], bn[b])
	if val == -1 {
		return true
	}
	return false
}

// ParseCIDR returns a new Net object. It is a passthrough to net.ParseCIDR
// and will return any error it generates to the caller. There is one major
// difference between how net.IPNet manages addresses and how ipnet.Net does,
// and this function exposes it: net.ParseCIDR *always* returns an IPv6
// address; if given a v4 address it returns the RFC4291 IPv4-mapped IPv6
// address internally, but treats it like v4 in practice. In contrast
// iplib.ParseCIDR will re-encode it as a v4
func ParseCIDR(s string) (net.IP, Net, error) {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return ip, nil, err
	}
	masklen, _ := ipnet.Mask.Size()

	if strings.Contains(s, ".") {
		return ForceIP4(ip), NewNet4(ForceIP4(ip), masklen), err
	}

	if EffectiveVersion(ip) == 4 && masklen <= 32 {
		return ip, NewNet4(ip, masklen), err
	}

	return ip, NewNet6(ip, masklen, 0), err
}

func fitNetworkBetween(a, b net.IP, mask int) (Net, bool, error) {
	xnet := NewNet(a, mask)

	va := CompareIPs(xnet.FirstAddress(), a)
	vb := CompareIPs(xnet.LastAddress(), b)
	if va >= 0 && vb < 0 {
		return xnet, false, nil
	}
	if va == 0 && vb == 0 {
		return xnet, true, nil
	}
	return fitNetworkBetween(a, b, mask + 1)
}