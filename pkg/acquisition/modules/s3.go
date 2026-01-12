//go:build !no_datasource_s3

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/s3" // register the datasource
