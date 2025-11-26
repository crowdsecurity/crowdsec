package s3acquisition

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

func (*Source) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{
		metrics.S3DataSourceLinesRead,
		metrics.S3DataSourceObjectsRead,
		metrics.S3DataSourceSQSMessagesReceived,
	}
}

func (*Source) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{
		metrics.S3DataSourceLinesRead,
		metrics.S3DataSourceObjectsRead,
		metrics.S3DataSourceSQSMessagesReceived,
	}
}
