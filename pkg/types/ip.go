package types

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/pkg/errors"
)

func LastAddress(n net.IPNet) net.IP {
	ip := n.IP.To4()
	if ip == nil {
		ip = n.IP
		return net.IP{
			ip[0] | ^n.Mask[0], ip[1] | ^n.Mask[1], ip[2] | ^n.Mask[2],
			ip[3] | ^n.Mask[3], ip[4] | ^n.Mask[4], ip[5] | ^n.Mask[5],
			ip[6] | ^n.Mask[6], ip[7] | ^n.Mask[7], ip[8] | ^n.Mask[8],
			ip[9] | ^n.Mask[9], ip[10] | ^n.Mask[10], ip[11] | ^n.Mask[11],
			ip[12] | ^n.Mask[12], ip[13] | ^n.Mask[13], ip[14] | ^n.Mask[14],
			ip[15] | ^n.Mask[15]}
	}

	return net.IPv4(
		ip[0]|^n.Mask[0],
		ip[1]|^n.Mask[1],
		ip[2]|^n.Mask[2],
		ip[3]|^n.Mask[3])
}

/*returns a range for any ip or range*/
func Addr2Ints(anyIP string) (int, int64, int64, int64, int64, error) {
	if strings.Contains(anyIP, "/") {
		_, net, err := net.ParseCIDR(anyIP)
		if err != nil {
			return -1, 0, 0, 0, 0, errors.Wrapf(err, "while parsing range %s", anyIP)
		}
		return Range2Ints(*net)
	}

	ip := net.ParseIP(anyIP)
	if ip == nil {
		return -1, 0, 0, 0, 0, fmt.Errorf("invalid address")
	}

	sz, start, end, err := IP2Ints(ip)
	if err != nil {
		return -1, 0, 0, 0, 0, errors.Wrapf(err, "while parsing ip %s", anyIP)
	}

	return sz, start, end, start, end, nil
}

/*size (16|4), nw_start, suffix_start, nw_end, suffix_end, error*/
func Range2Ints(network net.IPNet) (int, int64, int64, int64, int64, error) {

	szStart, nwStart, sfxStart, err := IP2Ints(network.IP)
	if err != nil {
		return -1, 0, 0, 0, 0, errors.Wrap(err, "converting first ip in range")
	}
	lastAddr := LastAddress(network)
	szEnd, nwEnd, sfxEnd, err := IP2Ints(lastAddr)
	if err != nil {
		return -1, 0, 0, 0, 0, errors.Wrap(err, "transforming last address of range")
	}
	if szEnd != szStart {
		return -1, 0, 0, 0, 0, fmt.Errorf("inconsistent size for range first(%d) and last(%d) ip", szStart, szEnd)
	}
	return szStart, nwStart, sfxStart, nwEnd, sfxEnd, nil
}

func uint2int(u uint64) int64 {
	var ret int64
	if u == math.MaxInt64 {
		ret = 0
	} else if u == math.MaxUint64 {
		ret = math.MaxInt64
	} else if u > math.MaxInt64 {
		u -= math.MaxInt64
		ret = int64(u)
	} else {
		ret = int64(u)
		ret -= math.MaxInt64
	}
	return ret
}

/*size (16|4), network, suffix, error*/
func IP2Ints(pip net.IP) (int, int64, int64, error) {
	var ip_nw, ip_sfx uint64

	pip4 := pip.To4()
	pip16 := pip.To16()

	if pip4 != nil {
		ip_nw32 := binary.BigEndian.Uint32(pip4)

		return 4, uint2int(uint64(ip_nw32)), uint2int(ip_sfx), nil
	} else if pip16 != nil {
		ip_nw = binary.BigEndian.Uint64(pip16[0:8])
		ip_sfx = binary.BigEndian.Uint64(pip16[8:16])
		return 16, uint2int(ip_nw), uint2int(ip_sfx), nil
	} else {
		return -1, 0, 0, fmt.Errorf("unexpected len %d for %s", len(pip), pip)
	}
}
