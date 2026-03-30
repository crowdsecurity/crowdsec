//go:build !no_datasource_kafka

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/kafka" // register the datasource
