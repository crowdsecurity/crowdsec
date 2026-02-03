//go:build !no_datasource_docker

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/docker" // register the datasource
