package types

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
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
func Addr2Ints(any string) (int, uint64, uint64, uint64, uint64, error) {
	if strings.Contains(any, "/") {
		_, net, err := net.ParseCIDR(any)
		if err != nil {
			return -1, 0, 0, 0, 0, errors.Wrapf(err, "while parsing range %s", any)
		}
		if net == nil {
			return -1, 0, 0, 0, 0, fmt.Errorf("empty/invalid range %s", any)
		}
		return Range2Ints(*net)
	} else {
		ip := net.ParseIP(any)
		sz, start, end, err := IP2Ints(ip)
		if err != nil {
			return -1, 0, 0, 0, 0, errors.Wrapf(err, "while parsing ip %s", any)
		}
		return sz, start, end, start, end, nil
	}
}

/*size (16|4), nw_start, suffix_start, nw_end, suffix_end, error*/
func Range2Ints(network net.IPNet) (int, uint64, uint64, uint64, uint64, error) {

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

/*size (16|4), network, suffix, error*/
func IP2Ints(pip net.IP) (int, uint64, uint64, error) {
	var ip_nw, ip_sfx uint64

	pip4 := pip.To4()
	pip16 := pip.To16()

	if pip4 != nil {
		ip_nw32 := binary.BigEndian.Uint32(pip4)
		return 4, uint64(ip_nw32), ip_sfx, nil
	} else if pip16 != nil {
		ip_nw = binary.BigEndian.Uint64(pip16[0:8])
		ip_sfx = binary.BigEndian.Uint64(pip16[8:16])
		return 16, ip_nw, ip_sfx, nil
	} else {
		return -1, 0, 0, fmt.Errorf("unexpected len %d for %s", len(pip), pip)
	}
}

/*
check_* is the range we want to know about
range_* is the existing decision

	(C.START > D.START OR (C.START == D.START AND C.START_SFX >= D.START_SFX))
	AND
	(C.END < D.END OR (C.END == D.END AND C.END_SFX <= D.END_SFX))
*/
func compare_RANGE_is_in(
	check_sz int, check_start_nw uint64, check_start_sfx uint64, check_end_nw uint64, check_end_sfx uint64,
	range_sz int, range_start_nw uint64, range_start_sfx uint64, range_end_nw uint64, range_end_sfx uint64) bool {

	/*ipv4 vs ipv6*/
	if check_sz != range_sz {
		log.Tracef("mismatch sizes (check:%d range:%d)", check_sz, range_sz)
		return false
	}
	if check_sz == 16 {

		/*
		 FOR IPV6 :
		  - verify that check_start{nw,sfx} is >= to range_start{nw,sfx}
		  - verify that check_end{nw,sfx} is <= to range_end{nw,sfx}
		*/
		if check_start_nw > range_start_nw ||
			(check_start_nw == range_start_nw && check_start_sfx >= range_start_sfx) {
			log.Tracef("%d,%d >= %d,%d", range_start_nw, range_start_sfx, check_start_nw, check_start_sfx)
			/*lower bound is ok*/
			if check_end_nw < range_end_nw ||
				(check_end_nw == range_end_nw && check_end_sfx <= range_end_sfx) {
				log.Tracef("%d,%d <= %d,%d", check_end_nw, check_end_sfx, range_end_nw, range_end_sfx)
				/*upper bound is ok*/
				log.Tracef("(ipv6) true: %d,%d <=(%d,%d)-(%d,%d) <= %d,%d",
					range_start_nw, range_start_sfx,
					check_start_nw, check_start_sfx,
					check_end_nw, check_end_sfx,
					range_end_nw, range_end_sfx)
				return true
			}
		}
		return false
	} else if check_sz == 4 {
		if range_start_nw <= check_start_nw &&
			check_end_nw <= range_end_nw {
			log.Tracef("(ipv4) true: %d,%d <=(%d,%d)-(%d,%d) <= %d,%d",
				range_start_nw, range_start_sfx,
				check_start_nw, check_start_sfx,
				check_end_nw, check_end_sfx,
				range_end_nw, range_end_sfx)
			return true
		}
	} else {
		log.Errorf("Unexpected addr size : %d", check_sz)
		return false
	}
	return false
}
