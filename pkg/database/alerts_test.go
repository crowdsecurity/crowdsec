package database

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAlertsCountPerScenario(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)

	for _, a := range []struct {
		scenario string
		kind     string
	}{
		{"ssh-bf", "crowdsec"},
		{"ssh-bf", "crowdsec"},
		{"ssh-bf", "waf"},
		{"vpatch", "waf"},
		{"legacy", ""}, // kind left NULL, as for alerts created before the field existed
	} {
		create := c.Ent.Alert.Create().SetScenario(a.scenario)
		if a.kind != "" {
			create = create.SetKind(a.kind)
		}

		_, err := create.Save(ctx)
		require.NoError(t, err)
	}

	counts, err := c.AlertsCountPerScenario(ctx, map[string][]string{})
	require.NoError(t, err)
	require.ElementsMatch(t, []AlertsByScenario{
		{Scenario: "ssh-bf", Kind: "crowdsec", Count: 2},
		{Scenario: "ssh-bf", Kind: "waf", Count: 1},
		{Scenario: "vpatch", Kind: "waf", Count: 1},
		{Scenario: "legacy", Kind: "", Count: 1},
	}, counts)
}
