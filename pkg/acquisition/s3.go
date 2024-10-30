//go:build !no_datasource_s3

package acquisition

import (
	s3acquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/s3"
)

//nolint:gochecknoinits
func init() {
	registerDataSource("s3", func() DataSource { return &s3acquisition.S3Source{} })
}
