// +build !no_datasource_file

package acquisition

import (
	fileacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file"
)

//nolint:gochecknoinits
func init() {
	AcquisitionSources["file"] = func() DataSource { return &fileacquisition.FileSource{} }
}
