package metrics

import (
	"slices"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	FeatureLAPI         = "lapi"
	FeatureCAPI         = "capi"
	FeatureLogProcessor = "log_processor"
	FeatureWAF          = "waf"
	FeatureBotDetection = "bot_detection"
	FeaturePAPI         = "papi"
)

// AllFeatures is every feature cs_features reports, enabled or not. Keep it sorted.
var AllFeatures = []string{FeatureBotDetection, FeatureCAPI, FeatureLAPI, FeatureLogProcessor, FeaturePAPI, FeatureWAF}

const FeaturesMetricName = "cs_features"

var Features = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: FeaturesMetricName,
		Help: "Features enabled on this instance (1 = enabled, 0 = disabled).",
	},
	[]string{"feature"},
)

// SetFeatures marks the given features as enabled, and all the others as disabled.
func SetFeatures(enabled []string) {
	for _, feature := range AllFeatures {
		value := 0.0
		if slices.Contains(enabled, feature) {
			value = 1
		}

		Features.WithLabelValues(feature).Set(value)
	}
}
