package kinesisacquisition

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

func (*Source) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{
		metrics.KinesisDataSourceLinesRead,
		metrics.KinesisDataSourceLinesReadShards,
	}
}

func (*Source) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{
		metrics.KinesisDataSourceLinesRead,
		metrics.KinesisDataSourceLinesReadShards,
	}
}
