// +build !no_datasource_cloudwatch

package acquisition

import (
	cloudwatchacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/cloudwatch"
)

//nolint:gochecknoinits
func init() {
	AcquisitionSources["cloudwatch"] = func() DataSource { return &cloudwatchacquisition.CloudwatchSource{} }
}
