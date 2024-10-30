package useragent

import (
	"github.com/crowdsecurity/go-cs-lib/version"
)

func Default() string {
	return "crowdsec/" + version.String() + "-" + version.System
}
