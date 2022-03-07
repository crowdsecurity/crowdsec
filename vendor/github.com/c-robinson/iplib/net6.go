package iplib

import (
	"math"
	"math/big"
	"net"
	"sort"
	"sync"
)

// Net6 is an implementation of Net that supports IPv6 operations. To
// initialize a Net6 you must supply a network address and mask prefix as
// with Net4, but you may also optionally supply an integer value between
// 0 and 128 that Net6 will mask out from the right, via a HostMask (see the
// documentation for HostMask in this library). If "0" HostMask will be
// ignored. The sum of netmask prefix and hostmask must be less than 128.
//
// Hostmask affects Count, Enumerate, LastAddress, NextIP and PreviousIP; it
// also affects NextNet and PreviousNet which will inherit the hostmask from
// their parent. Subnet and Supernet both require a hostmask in their function
// calls
type Net6 struct {
	net.IPNet
	Hostmask HostMask
}

// NewNet6 returns an initialized Net6 object at the specified netmasklen with
// the specified hostmasklen. If netmasklen or hostmasklen is greater than 128
// it will return an empty object; it will also return an empty object if the
// sum of the two masks is 128 or greater. If a v4 address is supplied it
// will be treated as a RFC4291 v6-encapsulated-v4 network (which is the
// default behavior for net.IP)
func NewNet6(ip net.IP, netmasklen, hostmasklen int) Net6 {
	var maskMax = 128
	if Version(ip) != IP6Version {
		return Net6{IPNet: net.IPNet{}, Hostmask: HostMask{}}
	}

	if (netmasklen == 127 || netmasklen == 128) && hostmasklen == 0 {
		netmask := net.CIDRMask(netmasklen, maskMax)
		n := net.IPNet{IP: ip.Mask(netmask), Mask: netmask}
		return Net6{IPNet: n, Hostmask: NewHostMask(0)}
	}

	if netmasklen+hostmasklen >= maskMax {
		return Net6{IPNet: net.IPNet{}, Hostmask: HostMask{}}
	}

	netmask := net.CIDRMask(netmasklen, maskMax)

	n := net.IPNet{IP: ip.Mask(netmask), Mask: netmask}
	return Net6{IPNet: n, Hostmask: NewHostMask(hostmasklen)}
}

// Net6FromStr takes a string which should be a v6 address in CIDR notation
// and returns an initialized Net6. If the string isn't parseable an empty
// Net6 will be returned
func Net6FromStr(s string) Net6 {
	_, n, err := ParseCIDR(s)
	if err != nil {
		return Net6{}
	}
	if n6, ok := n.(Net6); ok {
		return n6
	}
	return Net6{}
}

// Contains returns true if ip is contained in the represented netblock
func (n Net6) Contains(ip net.IP) bool {
	return n.IPNet.Contains(ip)
}

// ContainsNet returns true if the given Net is contained within the
// represented block
func (n Net6) ContainsNet(network Net) bool {
	l1, _ := n.Mask().Size()
	l2, _ := network.Mask().Size()
	return l1 <= l2 && n.Contains(network.IP())
}

// Controls returns true if ip is within the scope of the represented block,
// meaning that it is both inside of the netmask and outside of the hostmask.
// In other words this function will return true if ip would be enumerated by
// this Net6 instance
func (n Net6) Controls(ip net.IP) bool {
	if !n.Contains(ip) {
		return false
	}
	if !n.contained(ip) {
		return false
	}
	return true
}

// Count returns the number of IP addresses in the represented netblock
func (n Net6) Count() *big.Int {
	ones, all := n.Mask().Size()

	// first check if this is an RFC6164 point-to-point subnet
	exp := all - ones
	if exp == 1 {
		return big.NewInt(2) // special handling for RFC6164 /127
	}
	if exp == 0 {
		return big.NewInt(1) // special handling for /128
	}

	oneser, _ := n.Hostmask.Size()
	exp -= oneser
	var z, e = big.NewInt(2), big.NewInt(int64(exp))
	return z.Exp(z, e, nil)
}

// Enumerate generates an array of all usable addresses in Net up to the
// given size starting at the given offset, so long as the result is less than
// MaxUint32. If size=0 the entire block is enumerated (again, so long as the
// result is less than MaxUint32).
//
// For consistency, enumerating a /128 will return the IP in a 1 element array
func (n Net6) Enumerate(size, offset int) []net.IP {
	if n.IP() == nil {
		return nil
	}

	count := getEnumerationCount(size, offset, n.Count())

	// Handle edge-case mask sizes
	ones, _ := n.Mask().Size()
	if ones == 128 {
		return []net.IP{n.FirstAddress()}
	}

	if count < 1 {
		return []net.IP{}
	}

	addrs := make([]net.IP, count)

	fip := n.FirstAddress()
	if offset != 0 {
		fip, _ = IncrementIP6WithinHostmask(fip, n.Hostmask, big.NewInt(int64(offset)))
	}

	// for large requests ( >250 million) response times are very similar
	// across a wide-array of goroutine counts. Limiting the per-goroutine
	// workload in this way simply ensures that we [a] can dynamically expand
	// our worker-pool based on request size; and [b] don't have to worry
	// about exhausting some upper bound of goroutines -- enumerate requests
	// are limited to MaxInt32, so we won't generate more than 32768
	limit := uint32(65535)
	pos := uint32(0)
	wg := sync.WaitGroup{}
	for pos < count {
		incr := limit
		if limit > count - pos {
			incr = count - pos
		}
		wg.Add(1)
		go func(fip net.IP, pos, count uint32) {
			defer wg.Done()
			addrs[pos], _ = IncrementIP6WithinHostmask(fip, n.Hostmask, big.NewInt(int64(pos)))
			for i := uint32(1); i < count; i++ {
				pos++
				addrs[pos], _ = NextIP6WithinHostmask(addrs[pos-1], n.Hostmask)
			}
		}(fip, pos, incr)
		pos = pos + incr
	}
	wg.Wait()
	return addrs
}

// FirstAddress returns the first usable address for the represented network
func (n Net6) FirstAddress() net.IP {
	return getCloneIP(n.IP())
}

// LastAddress returns the last usable address for the represented network
func (n Net6) LastAddress() net.IP {
	xip := make([]byte, len(n.IPNet.IP))
	wc := n.wildcard()
	for pos := range n.IP() {
		xip[pos] = n.IP()[pos] + (wc[pos] - n.Hostmask[pos])
	}
	return xip
}

// Mask returns the netmask of the netblock
func (n Net6) Mask() net.IPMask {
	return n.IPNet.Mask
}

// IP returns the network address for the represented network, e.g.
// the lowest IP address in the given block
func (n Net6) IP() net.IP {
	return n.IPNet.IP
}

// NextIP takes a net.IP as an argument and attempts to increment it by one
// within the boundary of allocated network-bytes. If the resulting address is
// outside of the range of the represented network it will return an empty
// net.IP and an ErrAddressOutOfRange
func (n Net6) NextIP(ip net.IP) (net.IP, error) {
	xip, _ := NextIP6WithinHostmask(ip, n.Hostmask)
	if !n.Contains(xip) {
		return net.IP{}, ErrAddressOutOfRange
	}
	return xip, nil
}

// NextNet takes a CIDR mask-size as an argument and attempts to create a new
// Net object just after the current Net, at the requested mask length and
// with the same hostmask as the current Net
func (n Net6) NextNet(masklen int) Net6 {
	hmlen, _ := n.Hostmask.Size()
	if masklen == 0 {
		masklen, _ = n.Mask().Size()
	}
	nn := NewNet6(n.IP(), masklen, hmlen)
	xip, _ := NextIP6WithinHostmask(nn.LastAddress(), n.Hostmask)
	return NewNet6(xip, masklen, hmlen)
}

// PreviousIP takes a net.IP as an argument and attempts to decrement it by
// one within the boundary of the allocated network-bytes. If the resulting
// address is outside the range of the represented netblock it will return an
// empty net.IP and an ErrAddressOutOfRange
func (n Net6) PreviousIP(ip net.IP) (net.IP, error) {
	xip, _ := PreviousIP6WithinHostmask(ip, n.Hostmask)
	if !n.Contains(xip) {
		return net.IP{}, ErrAddressOutOfRange
	}
	return xip, nil
}

// PreviousNet takes a CIDR mask-size as an argument and creates a new Net
// object just before the current one, at the requested mask length. If the
// specified mask is for a larger network than the current one then the new
// network may encompass the current one
func (n Net6) PreviousNet(masklen int) Net6 {
	hmlen, _ := n.Hostmask.Size()
	if masklen == 0 {
		masklen, _ = n.Mask().Size()
	}
	nn := NewNet6(n.IP(), masklen, hmlen)
	xip, _ := PreviousIP6WithinHostmask(nn.IP(), n.Hostmask)
	return NewNet6(xip, masklen, hmlen)
}

// String returns the CIDR notation of the enclosed network e.g. 2001:db8::/16
func (n Net6) String() string {
	return n.IPNet.String()
}

// Subnet takes a CIDR mask-size as an argument and carves the current Net
// object into subnets of that size, returning them as a []Net. The mask
// provided must be a larger-integer than the current mask. If set to 0 Subnet
// will carve the network in half. Hostmask must be provided if desired
func (n Net6) Subnet(netmasklen, hostmasklen int) ([]Net6, error) {
	ones, all := n.Mask().Size()
	if netmasklen == 0 {
		netmasklen = ones + 1
	}
	if ones > netmasklen || (hostmasklen+netmasklen) > all {
		return nil, ErrBadMaskLength
	}

	mask := net.CIDRMask(netmasklen, all)
	netlist := []Net6{{IPNet: net.IPNet{IP: n.IP(), Mask: mask}, Hostmask: NewHostMask(hostmasklen)}}

	for CompareIPs(netlist[len(netlist)-1].LastAddress(), n.LastAddress()) == -1 {
		xip, _ := NextIP6WithinHostmask(netlist[len(netlist)-1].LastAddress(), n.Hostmask)
		if len(xip) == 0 || xip == nil {
			return netlist, nil
		}
		ng := net.IPNet{IP: xip, Mask: mask}
		netlist = append(netlist, Net6{ng, NewHostMask(hostmasklen)})
	}
	return netlist, nil
}

// Supernet takes a CIDR mask-size as an argument and returns a Net object
// containing the supernet of the current Net at the requested mask length.
// The mask provided must be a smaller-integer than the current mask. If set
// to 0 Supernet will return the next-largest network
func (n Net6) Supernet(netmasklen, hostmasklen int) (Net6, error) {
	ones, all := n.Mask().Size()
	if ones < netmasklen {
		return Net6{}, ErrBadMaskLength
	}

	if netmasklen == 0 {
		netmasklen = ones - 1
	}

	mask := net.CIDRMask(netmasklen, all)
	ng := net.IPNet{IP: n.IP().Mask(mask), Mask: mask}
	return Net6{ng, NewHostMask(hostmasklen)}, nil
}

// Version returns the version of IP for the enclosed netblock as an int. 6
// in this case
func (n Net6) Version() int {
	return IP6Version
}

// return true if 'ip' is within the hostmask of n
func (n Net6) contained(ip net.IP) bool {
	b, pos := n.Hostmask.BoundaryByte()
	if pos == -1 {
		return true
	}

	if ip[pos] > b {
		return false
	}
	for i := len(ip) - 1; i > pos; i-- {
		if ip[i] > 0 {
			return false
		}
	}
	return true
}

func (n Net6) wildcard() net.IPMask {
	wc := make([]byte, len(n.Mask()))
	for i, b := range n.Mask() {
		wc[i] = 0xff - b
	}
	return wc
}

// getEnumerationCount returns the size of the array needed to satisfy an
// Enumerate request. Mostly split out to ease testing of larger values
func getEnumerationCount(reqSize, offset int, count *big.Int) uint32 {
	sizes := []uint32{math.MaxUint32}

	if count.IsInt64() {
		realCount := uint32(0)
		if int(count.Int64()) > offset {
			realCount = uint32(count.Int64()) - uint32(offset)
		}
		sizes = append(sizes, realCount)
	}

	if uint32(reqSize) != 0 {
		sizes = append(sizes, uint32(reqSize))
	}

	sort.Slice(sizes, func(i, j int) bool { return sizes[i] < sizes[j] })

	return sizes[0]
}
