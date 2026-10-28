package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

type plainSource struct {
	types.DataSource
}

type featureSource struct {
	types.DataSource
	features []string
}

func (f featureSource) Features() []string {
	return f.features
}

func TestLPFeatures(t *testing.T) {
	waf := featureSource{features: []string{metrics.FeatureWAF}}
	bot := featureSource{features: []string{metrics.FeatureWAF, metrics.FeatureBotDetection}}

	tests := []struct {
		name    string
		lapi    []string
		sources []types.DataSource
		want    []string
	}{
		{
			name: "no datasource",
			want: []string{metrics.FeatureLogProcessor},
		},
		{
			name:    "datasources without features",
			sources: []types.DataSource{plainSource{}, plainSource{}},
			want:    []string{metrics.FeatureLogProcessor},
		},
		{
			name:    "several appsec sources, one with bot detection",
			sources: []types.DataSource{bot, plainSource{}, waf},
			want:    []string{metrics.FeatureBotDetection, metrics.FeatureLogProcessor, metrics.FeatureWAF},
		},
		{
			name:    "same process as the lapi",
			lapi:    []string{metrics.FeatureLAPI, metrics.FeatureCAPI},
			sources: []types.DataSource{waf},
			want:    []string{metrics.FeatureCAPI, metrics.FeatureLAPI, metrics.FeatureLogProcessor, metrics.FeatureWAF},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			datasources := make([]acquisition.ConfiguredSource, 0, len(tc.sources))
			for _, ds := range tc.sources {
				datasources = append(datasources, acquisition.ConfiguredSource{DataSource: ds})
			}

			require.Equal(t, tc.want, lpFeatures(tc.lapi, datasources))
		})
	}
}
