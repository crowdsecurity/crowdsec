package metrics

import (
	"slices"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestAllFeaturesSorted(t *testing.T) {
	require.True(t, slices.IsSorted(AllFeatures), "lists built from AllFeatures are expected to be sorted")
}

func TestSetFeatures(t *testing.T) {
	tests := []struct {
		name    string
		enabled []string
		want    map[string]float64
	}{
		{
			name:    "lapi and waf",
			enabled: []string{FeatureLAPI, FeatureWAF},
			want: map[string]float64{
				FeatureLAPI: 1, FeatureCAPI: 0, FeatureLogProcessor: 0, FeatureWAF: 1, FeatureBotDetection: 0, FeaturePAPI: 0,
			},
		},
		{
			name:    "capi",
			enabled: []string{FeatureLAPI, FeatureCAPI},
			want: map[string]float64{
				FeatureLAPI: 1, FeatureCAPI: 1, FeatureLogProcessor: 0, FeatureWAF: 0, FeatureBotDetection: 0, FeaturePAPI: 0,
			},
		},
		{
			// e.g. after a reload that removed the appsec datasource
			name:    "previously enabled features are reset",
			enabled: []string{FeatureLogProcessor},
			want: map[string]float64{
				FeatureLAPI: 0, FeatureCAPI: 0, FeatureLogProcessor: 1, FeatureWAF: 0, FeatureBotDetection: 0, FeaturePAPI: 0,
			},
		},
		{
			name:    "unknown features are ignored",
			enabled: []string{"nope"},
			want: map[string]float64{
				FeatureLAPI: 0, FeatureCAPI: 0, FeatureLogProcessor: 0, FeatureWAF: 0, FeatureBotDetection: 0, FeaturePAPI: 0,
			},
		},
	}

	// sequential on purpose, each case runs over the state left by the previous one
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			SetFeatures(tc.enabled)

			require.Equal(t, len(AllFeatures), testutil.CollectAndCount(Features))

			for feature, want := range tc.want {
				require.InDelta(t, want, testutil.ToFloat64(Features.WithLabelValues(feature)), 0, feature)
			}
		})
	}
}
