package apiserver

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLAPIFeatures(t *testing.T) {
	tests := []struct {
		name string
		apic *apic
		papi *Papi
		want []string
	}{
		{
			name: "no online client",
			want: []string{"lapi"},
		},
		{
			name: "capi, not enrolled",
			apic: &apic{},
			want: []string{"capi", "lapi"},
		},
		{
			name: "enrolled without papi_url",
			apic: &apic{},
			papi: &Papi{},
			want: []string{"capi", "lapi"},
		},
		{
			name: "enrolled with papi",
			apic: &apic{},
			papi: &Papi{URL: "https://papi.api.crowdsec.net/"},
			want: []string{"capi", "lapi", "papi"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, lapiFeatures(tc.apic, tc.papi))
		})
	}
}
