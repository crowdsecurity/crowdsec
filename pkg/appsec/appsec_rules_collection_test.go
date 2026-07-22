package appsec

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// withCollection swaps in a fresh set of package globals for the duration of a
// test and restores them afterwards. LoadCollection reads appsecRules and
// writes AppsecRulesDetails, both of which are package-level state.
func withCollection(t *testing.T, cfg AppsecCollectionConfig) {
	t.Helper()

	savedRules := appsecRules
	savedDetails := AppsecRulesDetails

	t.Cleanup(func() {
		appsecRules = savedRules
		AppsecRulesDetails = savedDetails
	})

	appsecRules = map[string]AppsecCollectionConfig{cfg.Name: cfg}
	AppsecRulesDetails = make(map[int]RulesDetails)
}

// TestLoadCollectionRegistersAllRuleIDs: every SecRule from an `or` rule must
// be registered, so any matching branch resolves to the rule name instead of
// being mistaken for a native seclang rule. Regression test for #4340.
func TestLoadCollectionRegistersAllRuleIDs(t *testing.T) {
	orRule := appsec_rule.CustomRule{
		Or: []appsec_rule.CustomRule{
			{Zones: []string{"ARGS"}, Variables: []string{"foo"}, Match: appsec_rule.Match{Type: "equals", Value: "toto"}},
			{Zones: []string{"ARGS"}, Variables: []string{"bar"}, Match: appsec_rule.Match{Type: "equals", Value: "tutu"}},
			{Zones: []string{"ARGS"}, Variables: []string{"baz"}, Match: appsec_rule.Match{Type: "equals", Value: "titi"}},
		},
	}

	cfg := AppsecCollectionConfig{
		Name:        "test/or-rule",
		Description: "my or rule description",
		Rules:       []appsec_rule.CustomRule{orRule},
		hash:        "deadbeef",
		version:     "1.2.3",
	}

	// Compute the full set of generated ids independently of LoadCollection.
	// orRule is the first (index 0) rule of the collection.
	_, expectedIDs, err := orRule.Convert(appsec_rule.ModsecurityRuleType, cfg.Name, cfg.Description, 0)
	require.NoError(t, err)
	// An `or` with three branches must produce more than one rule, otherwise
	// this test would not actually exercise the bug.
	require.Greater(t, len(expectedIDs), 1)

	withCollection(t, cfg)

	_, err = LoadCollection(cfg.Name, log.NewEntry(log.StandardLogger()), &cwhub.Hub{})
	require.NoError(t, err)

	// Every generated id (not just the first) must resolve to the rule details.
	for _, id := range expectedIDs {
		details, ok := AppsecRulesDetails[int(id)]
		require.Truef(t, ok, "id %d not registered in AppsecRulesDetails", id)
		require.Equal(t, cfg.Name, details.Name)
		require.Equal(t, cfg.hash, details.Hash)
		require.Equal(t, cfg.version, details.Version)
	}
}

// TestLoadCollectionNoCrossRuleIDCollision reproduces
// crowdsecurity/vpatch-CVE-2024-34102: a collection whose two rules share an
// identical leaf must still generate distinct, registered ids (no "conflicting
// id" warning).
func TestLoadCollectionNoCrossRuleIDCollision(t *testing.T) {
	sharedLeaf := appsec_rule.CustomRule{
		Zones:     []string{"URI"},
		Transform: []string{"lowercase"},
		Match:     appsec_rule.Match{Type: "contains", Value: "/admin"},
	}

	cfg := AppsecCollectionConfig{
		Name: "test/shared-leaf",
		Rules: []appsec_rule.CustomRule{
			{And: []appsec_rule.CustomRule{
				{Zones: []string{"METHOD"}, Match: appsec_rule.Match{Type: "equals", Value: "POST"}},
				sharedLeaf,
			}},
			{And: []appsec_rule.CustomRule{
				{Zones: []string{"METHOD"}, Match: appsec_rule.Match{Type: "equals", Value: "GET"}},
				sharedLeaf,
			}},
		},
		hash:    "cafe",
		version: "1.0.0",
	}

	withCollection(t, cfg)

	_, err := LoadCollection(cfg.Name, log.NewEntry(log.StandardLogger()), &cwhub.Hub{})
	require.NoError(t, err)

	// Both rules generate 2 leaves each. The shared URI leaf must not collapse
	// two of them into one id.
	require.Len(t, AppsecRulesDetails, 4, "expected 4 distinct ids across the collection's two rules")

	for id, details := range AppsecRulesDetails {
		require.Equalf(t, cfg.Name, details.Name, "id %d resolved to wrong rule name", id)
	}
}
