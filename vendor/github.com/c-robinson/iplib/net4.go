package iplib

import (
	"math"
	"net"
	"sync"
)

// Net4 is an implementation of Net intended for IPv4 netblocks. It has
// functions to return the broadcast address and wildcard mask not present in
// the IPv6 implementation
type Net4 struct {
	net.IPNet
	is4in6 bool
}

// NewNet4 returns an initialized Net4 object at the specified masklen. If
// mask is greater than 32, or if a v6 address is supplied, an empty Net4
// will be returned
func NewNet4(ip net.IP, masklen int) Net4 {
	var maskMax = 32
	if masklen > maskMax {
		return Net4{IPNet: net.IPNet{}}
	}
	mask := net.CIDRMask(masklen, maskMax)

	n := net.IPNet{IP: ForceIP4(ip).Mask(mask), Mask: mask}
	return Net4{IPNet: n, is4in6: Is4in6(ip)}
}

// Net4FromStr takes a string which should be a v4 address in CIDR notation
// and returns an initialized Net4. If the string isn't parseable an empty
// Net4 will be returned
func Net4FromStr(s string) Net4 {
	_, n, err := ParseCIDR(s)
	if err != nil {
		return Net4{}
	}
	if n4, ok := n.(Net4); ok {
		return n4
	}
	return Net4{}
}

// BroadcastAddress returns the broadcast address for the represented network.
// In the context of IPv6 broadcast is meaningless and the value will be
// equivalent to LastAddress().
func (n Net4) BroadcastAddress() net.IP {
	xip, _ := n.finalAddress()
	return xip
}

// Contains returns true if ip is contained in the represented netblock
func (n Net4) Contains(ip net.IP) bool {
	return n.IPNet.Contains(ip)
}

// ContainsNet returns true if the given Net is contained within the
// represented block
func (n Net4) ContainsNet(network Net) bool {
	l1, _ := n.Mask().Size()
	l2, _ := network.Mask().Size()
	return l1 <= l2 && n.Contains(network.IP())
}

// Count returns the total number of usable IP addresses in the represented
// network..
func (n Net4) Count() uint32 {
	ones, all := n.Mask().Size()
	exp := all - ones
	if exp == 1 {
		return uint32(2) // special handling for RFC3021 /31
	}
	if exp == 0 {
		return uint32(1) // special handling for /32
	}
	return uint32(math.Pow(2, float64(exp))) - 2
}

// Enumerate generates an array of all usable addresses in Net up to the
// given size starting at the given offset. If size=0 the entire block is
// enumerated.
//
// NOTE: RFC3021 defines a use case for netblocks of /31 for use in point-to-
// point links. For this reason enumerating networks at these lengths will
// return a 2-element array even though it would naturally return none.
//
// For consistency, enumerating a /32 will return the IP in a 1 element array
func (n Net4) Enumerate(size, offset int) []net.IP {
	if n.IP() == nil {
		return nil
	}

	count := int(n.Count())

	// offset exceeds total, return an empty array
	if offset > count {
		return []net.IP{}
	}

	// size is greater than the number of addresses that can be returned,
	// adjust the size of the slice but keep going
	if size > (count-offset) || size == 0 {
		size = count - offset
	}

	// Handle edge-case mask sizes
	if count == 1 { // Count() returns 1 if host-bits == 0
		return []net.IP{getCloneIP(n.IPNet.IP)}
	}

	addrs := make([]net.IP, size)

	netu := IP4ToUint32(n.FirstAddress())
	netu += uint32(offset)

	fip := Uint32ToIP4(netu)

	limit := 65535
	pos := 0
	wg := sync.WaitGroup{}
	for pos < size {
		incr := limit
		if limit > (size - pos) {
			incr = size - pos
		}
		wg.Add(1)
		go func(fip net.IP, pos, count int) {
			defer wg.Done()
			addrs[pos] = IncrementIP4By(fip, uint32(pos))
			for i := 1; i < count; i++ {
				pos++
				addrs[pos] = NextIP(addrs[pos-1])
			}
		}(fip, pos, incr)
		pos = pos + incr
	}
	wg.Wait()
	return addrs
}

// FirstAddress returns the first usable address for the represented network
func (n Net4) FirstAddress() net.IP {
	ones, _ := n.Mask().Size()

	// if it's either a single IP or RFC 3021, return the network address
	if ones >= 31 {
		return n.IPNet.IP
	}
	return NextIP(n.IP())
}

// Is4in6 will return true if this Net4 object or any of its parents were
// explicitly initialized with a 4in6 address (::ffff:xxxx.xxx)
func (n Net4) Is4in6() bool {
	return n.is4in6
}

// LastAddress returns the last usable address for the represented network
func (n Net4) LastAddress() net.IP {
	xip, ones := n.finalAddress()

	// if it's either a single IP or RFC 3021, return the last address
	if ones >= 31 {
		return xip
	}

	return PreviousIP(xip)
}

// Mask returns the netmask of the netblock
func (n Net4) Mask() net.IPMask {
	return n.IPNet.Mask
}

// IP returns the network address for the represented network, e.g.
// the lowest IP address in the given block
func (n Net4) IP() net.IP {
	return n.IPNet.IP
}

// NetworkAddress returns the network address for the represented network, e.g.
// the lowest IP address in the given block
func (n Net4) NetworkAddress() net.IP {
	return n.IPNet.IP
}

// NextIP takes a net.IP as an argument and attempts to increment it by one.
// If the resulting address is outside of the range of the represented network
// it will return an empty net.IP and an ErrAddressOutOfRange. If the result
// is the broadcast address, the address _will_ be returned, but so will an
// ErrBroadcastAddress, to indicate that the address is technically
// outside the usable scope
func (n Net4) NextIP(ip net.IP) (net.IP, error) {
	if !n.Contains(ip) {
		return net.IP{}, ErrAddressOutOfRange
	}
	xip := NextIP(ip)
	if !n.Contains(xip) {
		return net.IP{}, ErrAddressOutOfRange
	}
	// if this is the broadcast address, return it but warn the caller via error
	if n.BroadcastAddress().Equal(xip) {
		return xip, ErrBroadcastAddress
	}
	return xip, nil
}

// NextNet takes a CIDR mask-size as an argument and attempts to create a new
// Net object just after the current Net, at the requested mask length
func (n Net4) NextNet(masklen int) Net4 {
	return NewNet4(NextIP(n.BroadcastAddress()), masklen)
}

// PreviousIP takes a net.IP as an argument and attempts to decrement it by
// one. If the resulting address is outside of the range of the represented
// network it will return an empty net.IP and an ErrAddressOutOfRange. If the
// result is the network address, the address _will_ be returned, but so will
// an ErrNetworkAddress, to indicate that the address is technically outside
// the usable scope
func (n Net4) PreviousIP(ip net.IP) (net.IP, error) {
	if !n.Contains(ip) {
		return net.IP{}, ErrAddressOutOfRange
	}
	xip := PreviousIP(ip)
	if !n.Contains(xip) {
		return net.IP{}, ErrAddressOutOfRange
	}
	// if this is the network address, return it but warn the caller via error
	if n.IP().Equal(xip) {
		return xip, ErrNetworkAddress
	}
	return xip, nil
}

// PreviousNet takes a CIDR mask-size as an argument and creates a new Net
// object just before the current one, at the requested mask length. If the
// specified mask is for a larger network than the current one then the new
// network may encompass the current one, e.g.:
//
// iplib.Net{192.168.4.0/22}.Subnet(21) -> 192.168.0.0/21
//
// In the above case 192.168.4.0/22 is part of 192.168.0.0/21
func (n Net4) PreviousNet(masklen int) Net4 {
	return NewNet4(PreviousIP(n.IP()), masklen)
}

// String returns the CIDR notation of the enclosed network e.g. 192.168.0.1/24
func (n Net4) String() string {
	return n.IPNet.String()
}

// Subnet takes a CIDR mask-size as an argument and carves the current Net
// object into subnets of that size, returning them as a []Net. The mask
// provided must be a larger-integer than the current mask. If set to 0 Subnet
// will carve the network in half
func (n Net4) Subnet(masklen int) ([]Net4, error) {
	ones, all := n.Mask().Size()
	if masklen == 0 {
		masklen = ones + 1
	}

	if ones > masklen || masklen > all {
		return nil, ErrBadMaskLength
	}

	mask := net.CIDRMask(masklen, all)
	netlist := []Net4{{IPNet: net.IPNet{IP: n.IP(), Mask: mask}, is4in6: n.is4in6}}

	for CompareIPs(netlist[len(netlist)-1].BroadcastAddress(), n.BroadcastAddress()) == -1 {
		ng := net.IPNet{IP: NextIP(netlist[len(netlist)-1].BroadcastAddress()), Mask: mask}
		netlist = append(netlist, Net4{ng, n.is4in6})
	}
	return netlist, nil
}

// Supernet takes a CIDR mask-size as an argument and returns a Net object
// containing the supernet of the current Net at the requested mask length.
// The mask provided must be a smaller-integer than the current mask. If set
// to 0 Supernet will return the next-largest network
//
// Examples:
// Net{192.168.1.0/24}.Supernet(0)  -> Net{192.168.0.0/23}
// Net{192.168.1.0/24}.Supernet(22) -> Net{Net{192.168.0.0/22}
func (n Net4) Supernet(masklen int) (Net4, error) {
	ones, all := n.Mask().Size()
	if ones < masklen {
		return Net4{}, ErrBadMaskLength
	}

	if masklen == 0 {
		masklen = ones - 1
	}

	mask := net.CIDRMask(masklen, all)
	ng := net.IPNet{IP: n.IP().Mask(mask), Mask: mask}
	return Net4{ng, n.is4in6}, nil
}

// Version returns the version of IP for the enclosed netblock, 4 in this case
func (n Net4) Version() int {
	return IP4Version
}

// Wildcard will return the wildcard mask for a given netmask
func (n Net4) Wildcard() net.IPMask {
	wc := make([]byte, len(n.Mask()))
	for pos, b := range n.Mask() {
		wc[pos] = 0xff - b
	}
	return wc
}

// finalAddress returns the last address in the network. It is private
// because both LastAddress() and BroadcastAddress() rely on it, and both use
// it differently. It returns the last address in the block as well as the
// number of masked bits as an int.
func (n Net4) finalAddress() (net.IP, int) {
	xip := make([]byte, len(n.IP()))
	ones, _ := n.Mask().Size()

	// apply wildcard to network, byte by byte
	wc := n.Wildcard()
	for pos, b := range []byte(n.IP()) {
		xip[pos] = b + wc[pos]
	}
	return xip, ones
}
