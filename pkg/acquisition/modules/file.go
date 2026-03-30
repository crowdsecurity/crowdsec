//go:build !no_datasource_file

package modules

import _ "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file" // register the datasource
