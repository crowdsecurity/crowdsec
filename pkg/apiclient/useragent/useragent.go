package useragent

import (
	"github.com/crowdsecurity/go-cs-lib/version"
)

func Default() string {
	return "crowdsec/" + version.String() + "-" + version.System
}

func AppsecUserAgent() string {
	return "appsec/" + version.String() + "-" + version.System
}
