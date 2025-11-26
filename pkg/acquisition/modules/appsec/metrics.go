package appsecacquisition

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

func (*Source) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{
		metrics.AppsecReqCounter,
		metrics.AppsecBlockCounter,
		metrics.AppsecRuleHits,
		metrics.AppsecOutbandParsingHistogram,
		metrics.AppsecInbandParsingHistogram,
		metrics.AppsecGlobalParsingHistogram,
	}
}

func (*Source) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{
		metrics.AppsecReqCounter,
		metrics.AppsecBlockCounter,
		metrics.AppsecRuleHits,
		metrics.AppsecOutbandParsingHistogram,
		metrics.AppsecInbandParsingHistogram,
		metrics.AppsecGlobalParsingHistogram,
	}
}
