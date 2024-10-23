package clialert

import (
	"fmt"
	"net"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// SanitizeScope validates ip and range and sets the scope accordingly to our case convention.
func SanitizeScope(scope, ip, ipRange string) (string, error) {
	if ipRange != "" {
		_, _, err := net.ParseCIDR(ipRange)
		if err != nil {
			return "", fmt.Errorf("%s is not a valid range", ipRange)
		}
	}

	if ip != "" {
		if net.ParseIP(ip) == nil {
			return "", fmt.Errorf("%s is not a valid ip", ip)
		}
	}

	return types.NormalizeScope(scope), nil
}
