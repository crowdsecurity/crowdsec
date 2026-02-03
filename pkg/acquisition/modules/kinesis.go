//go:build !no_datasource_kinesis

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kinesis" // register the datasource
