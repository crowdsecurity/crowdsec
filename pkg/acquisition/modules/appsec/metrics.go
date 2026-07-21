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
		metrics.AppsecFingerprintMismatch,
		metrics.AppsecChallengeRequested,
		metrics.AppsecChallengeSubmitted,
		metrics.AppsecChallengeAccepted,
		metrics.AppsecChallengeRejected,
		metrics.AppsecChallengeExempt,
		metrics.AppsecChallengeKepochGenerated,
		metrics.AppsecChallengeKepochEvicted,
		metrics.AppsecChallengeReobfuscation,
		metrics.AppsecChallengeDynamicModuleEvicted,
		metrics.AppsecValidationOKCounter,
		metrics.AppsecValidationFailedCounter,
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
		metrics.AppsecFingerprintMismatch,
		metrics.AppsecChallengeRequested,
		metrics.AppsecChallengeSubmitted,
		metrics.AppsecChallengeAccepted,
		metrics.AppsecChallengeRejected,
		metrics.AppsecChallengeExempt,
		metrics.AppsecChallengeKepochGenerated,
		metrics.AppsecChallengeKepochEvicted,
		metrics.AppsecChallengeReobfuscation,
		metrics.AppsecChallengeDynamicModuleEvicted,
		metrics.AppsecOutbandParsingHistogram,
		metrics.AppsecValidationOKCounter,
		metrics.AppsecValidationFailedCounter,
		metrics.AppsecInbandParsingHistogram,
		metrics.AppsecGlobalParsingHistogram,
	}
}
