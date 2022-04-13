package cwhub

import (
	"testing"

	"github.com/stretchr/testify/require"
)

//Download index, install collection. Add scenario to collection (hub-side), update index, upgrade collection
func TestUpgradeConfigNewScenarioInCollection(t *testing.T) {
	cfg := test_prepenv()

	// fresh install of collection
	if err := GetHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to load hub index")
	}

	require.False(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.False(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Installed)

	require.NoError(t, InstallItem(cfg, "crowdsecurity/test_collection", COLLECTIONS, false, false))

	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)
	require.False(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)

	// This is the sceanrio that gets added in next version of collection
	require.False(t, hubIdx[SCENARIOS]["crowdsecurity/barfoo_scenario"].Downloaded)
	require.False(t, hubIdx[SCENARIOS]["crowdsecurity/barfoo_scenario"].Installed)

	assertCollectionDepsInstalled(t, "crowdsecurity/test_collection")

	// collection receives an update. It now adds new scenario "crowdsecurity/barfoo_scenario"
	responseByPath["/master/.index.json"] = fileToStringX("./tests/index2.json")
	responseByPath["/master/collections/crowdsecurity/test_collection.yaml"] = fileToStringX("./tests/collection_v2.yaml")
	if err := UpdateHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to download index : %s", err)
	}
	if err := GetHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to load hub index")
	}

	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.False(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)
	require.False(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)

	UpgradeConfig(cfg, COLLECTIONS, "crowdsecurity/test_collection", false)
	assertCollectionDepsInstalled(t, "crowdsecurity/test_collection")

	require.True(t, hubIdx[SCENARIOS]["crowdsecurity/barfoo_scenario"].Downloaded)
	require.True(t, hubIdx[SCENARIOS]["crowdsecurity/barfoo_scenario"].Installed)

}

func assertCollectionDepsInstalled(t *testing.T, collection string) {
	t.Helper()
	for _, parser := range hubIdx[COLLECTIONS][collection].Parsers {
		require.True(t, hubIdx[PARSERS][parser].Installed)
		require.True(t, hubIdx[PARSERS][parser].Downloaded)
		require.True(t, hubIdx[PARSERS][parser].UpToDate)
		require.False(t, hubIdx[PARSERS][parser].Tainted)
	}

	for _, scenario := range hubIdx[SCENARIOS][collection].Parsers {
		require.True(t, hubIdx[PARSERS][scenario].Installed)
		require.True(t, hubIdx[PARSERS][scenario].Downloaded)
		require.True(t, hubIdx[PARSERS][scenario].UpToDate)
		require.False(t, hubIdx[PARSERS][scenario].Tainted)
	}
}
