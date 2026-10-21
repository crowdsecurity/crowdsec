package csnet

import (
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"strings"
)

type IPAddrSize int

const (
	IPv4Size IPAddrSize = 4
	IPv6Size IPAddrSize = 16
)

type IntIP struct {
	size IPAddrSize
	Addr int64
	Sfx  int64
}

type Range struct {
	Start IntIP
	End   IntIP
}

func (r Range) Size() int {
	return int(r.Start.size)
}

// NewIP converts a netip.Addr into an IntIP for storage and comparison.
func NewIP(addr netip.Addr) IntIP {
	if addr.Is4() {
		ipBytes := addr.As4()

		return IntIP{
			size: IPv4Size,
			Addr: uint2int(uint64(binary.BigEndian.Uint32(ipBytes[:]))),
			Sfx:  0,
		}
	}

	ipBytes := addr.As16()

	return IntIP{
		size: IPv6Size,
		Addr: uint2int(binary.BigEndian.Uint64(ipBytes[0:8])),
		Sfx:  uint2int(binary.BigEndian.Uint64(ipBytes[8:16])),
	}
}

// NewRange parses an IP or CIDR string into a Range of IntIP addresses.
// If the input is a single IP (e.g. "1.2.3.4"), the start and end of the range are equal.
// If the input is a prefix (e.g. "1.2.3.0/24"), the function computes the first and last
// addresses covered by the prefix.
func NewRange(anyIP string) (Range, error) {
	if !strings.Contains(anyIP, "/") {
		addr, err := netip.ParseAddr(anyIP)
		if err != nil {
			return Range{}, err
		}

		ip := NewIP(addr)

		return Range{Start: ip, End: ip}, nil
	}

	prefix, err := netip.ParsePrefix(anyIP)
	if err != nil {
		return Range{}, err
	}

	start := prefix.Masked().Addr()
	bits := prefix.Bits()

	if start.Is4In6() && bits < 96 {
		return Range{}, errors.New("prefix with 4in6 address must have mask >= 96")
	}

	a16 := start.As16()

	if start.Is4() {
		bits += 96
	}

	// Fill host bits with 1s
	for b := bits; b < 128; b++ {
		a16[b/8] |= 1 << (7 - (b % 8))
	}

	end := netip.AddrFrom16(a16)
	if start.Is4() {
		end = end.Unmap()
	}

	return Range{Start: NewIP(start), End: NewIP(end)}, nil
}

func uint2int(u uint64) int64 {
	switch {
	case u == math.MaxInt64:
		return 0
	case u == math.MaxUint64:
		return math.MaxInt64
	case u > math.MaxInt64:
		return int64(u - math.MaxInt64)
	default:
		return int64(u) - math.MaxInt64
	}
}
