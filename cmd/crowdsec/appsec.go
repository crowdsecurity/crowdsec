//go:build !no_datasource_appsec

package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func LoadAppsecRules(hub *cwhub.Hub) error {
	if err := appsec.LoadAppsecRules(hub); err != nil {
		return fmt.Errorf("while loading appsec rules: %w", err)
	}

	return nil
}
