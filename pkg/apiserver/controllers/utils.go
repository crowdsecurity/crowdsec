package controllers

import (
	"encoding/binary"
	"fmt"
	"net"
)

func IP2Int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func Int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func IsIpv4(host string) bool {
	return net.ParseIP(host) != nil
}

//Stolen from : https://github.com/llimllib/ipaddress/
// Return the final address of a net range. Convert to IPv4 if possible,
// otherwise return an ipv6
func LastAddress(n *net.IPNet) net.IP {
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

func GetIpsFromIpRange(host string) (int64, int64, error) {
	var ipStart int64
	var ipEnd int64
	var err error
	var parsedRange *net.IPNet

	if _, parsedRange, err = net.ParseCIDR(host); err != nil {
		return ipStart, ipEnd, fmt.Errorf("'%s' is not a valid CIDR", host)
	}
	if parsedRange == nil {
		return ipStart, ipEnd, fmt.Errorf("unable to parse network : %s", err)
	}
	ipStart = int64(IP2Int(parsedRange.IP))
	ipEnd = int64(IP2Int(LastAddress(parsedRange)))

	return ipStart, ipEnd, nil
}
