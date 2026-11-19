package appsec

import (
	"testing"

	"github.com/expr-lang/expr"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/hookreq"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

func TestNewParsedRequestGeo(t *testing.T) {
	logger := log.WithField("test", "geo")

	tests := []struct {
		name     string
		clientIP string
		noDB     bool
		want     hookreq.Geo
	}{
		{
			name:     "all fields",
			clientIP: "89.160.20.112",
			want:     hookreq.Geo{Country: "SE", ASNumber: 29518, ASOrg: "Bredband2 AB", Range: "89.160.0.0/17", IsInEU: true},
		},
		{
			name:     "outside EU",
			clientIP: testIPUS,
			want:     hookreq.Geo{Country: "US", ASNumber: 209, Range: "216.160.64.0/18"},
		},
		{name: "private IP", clientIP: "10.0.0.1"},
		{name: "unparsable IP", clientIP: "not-an-ip"},
		{name: "no database", clientIP: "89.160.20.112", noDB: true},
	}

	t.Cleanup(exprhelpers.GeoIPClose)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.noDB {
				exprhelpers.GeoIPClose()
			} else {
				setupGeoIP(t)
			}

			r := makeTestRequest(t, nil)
			r.Header.Set(IPHeaderName, tc.clientIP)

			parsed, err := NewParsedRequestFromRequest(r, logger, BodySettings{})
			require.NoError(t, err)
			require.Equal(t, tc.want, parsed.HookRequest.Geo)
		})
	}
}

func TestHookReqGeo(t *testing.T) {
	setupGeoIP(t)
	t.Cleanup(exprhelpers.GeoIPClose)

	r := makeTestRequest(t, nil)
	r.Header.Set(IPHeaderName, "89.160.20.112")

	parsed, err := NewParsedRequestFromRequest(r, log.WithField("test", "geo"), BodySettings{})
	require.NoError(t, err)

	const filter = `req.Geo.Country == "SE" && req.Geo.IsInEU && req.Geo.ASNumber == 29518 && req.Geo.ASOrg == "Bredband2 AB" && req.Geo.Range == "89.160.0.0/17"`

	for _, stage := range reqStages {
		t.Run(stage.String(), func(t *testing.T) {
			h := &Hook{Filter: filter}
			require.NoError(t, h.Build(t.Context(), stage, nil))

			state := &AppsecRequestState{HookVars: map[string]string{}}
			env := scoreEnvForStage(stage, makeRuntime(), state, &parsed)

			got, err := expr.Run(h.FilterExpr, env)
			require.NoError(t, err)
			require.Equal(t, true, got)
		})
	}
}
