//go:build !no_datasource_cloudwatch

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/cloudwatch" // register the datasource
