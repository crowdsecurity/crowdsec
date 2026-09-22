package database

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csnet"
)

func TestAlertIPFilterMatchesOneDecision(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)

	// one alert with many decisions, as created by a blocklist pull
	for _, values := range [][]string{{"1.2.3.4", "9.9.9.9"}, {"2001:db8::1", "2001:db8::9"}} {
		owner, err := c.Ent.Alert.Create().SetScenario("test").Save(ctx)
		require.NoError(t, err)

		for _, value := range values {
			rng, err := csnet.NewRange(value)
			require.NoError(t, err)

			_, err = c.Ent.Decision.Create().
				SetUntil(time.Now().UTC().Add(time.Hour)).
				SetScenario("test").
				SetType("ban").
				SetScope("Ip").
				SetValue(value).
				SetOrigin("lists").
				SetStartIP(rng.Start.Addr).
				SetStartSuffix(rng.Start.Sfx).
				SetEndIP(rng.End.Addr).
				SetEndSuffix(rng.End.Sfx).
				SetIPSize(int64(rng.Size())).
				SetOwner(owner).
				Save(ctx)
			require.NoError(t, err)
		}
	}

	tests := []struct {
		name   string
		filter map[string][]string
		want   int
	}{
		{"ipv4 decision", map[string][]string{"ip": {"1.2.3.4"}}, 1},
		{"ipv4 between decisions", map[string][]string{"ip": {"5.5.5.5"}}, 0},
		{"ipv4 range between decisions", map[string][]string{"range": {"5.5.5.0/24"}, "contains": {"false"}}, 0},
		{"ipv6 decision", map[string][]string{"ip": {"2001:db8::1"}}, 1},
		{"ipv6 between decisions", map[string][]string{"ip": {"2001:db8::5"}}, 0},
		{"ipv6 range between decisions", map[string][]string{"range": {"2001:db8::4/127"}, "contains": {"false"}}, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			alerts, err := c.QueryAlertWithFilter(ctx, tc.filter)
			require.NoError(t, err)
			require.Len(t, alerts, tc.want)
		})
	}
}
