package useragent

import (
	"github.com/crowdsecurity/go-cs-lib/version"
)

func DefaultUserAgent() string {
	return "crowdsec/" + version.String() + "-" + version.System
}

