//go:build no_datasource_appsec

package main

import (
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func LoadAppsecRules(hub *cwhub.Hub) error {
	return nil
}
