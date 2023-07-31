package cwhub

import (
	"testing"

	"github.com/stretchr/testify/require"
)

//Download index, install collection. Add scenario to collection (hub-side), update index, upgrade collection
// We expect the new scenario to be installed
func TestUpgradeConfigNewScenarioInCollection(t *testing.T) {
	cfg := envSetup(t)
	defer envTearDown(cfg)

	// fresh install of collection
	getHubIdxOrFail(t)

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
	pushUpdateToCollectionInHub()

	if err := UpdateHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to download index : %s", err)
	}
	getHubIdxOrFail(t)

	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.False(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)
	require.False(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)

	UpgradeConfig(cfg, COLLECTIONS, "crowdsecurity/test_collection", false)
	assertCollectionDepsInstalled(t, "crowdsecurity/test_collection")

	require.True(t, hubIdx[SCENARIOS]["crowdsecurity/barfoo_scenario"].Downloaded)
	require.True(t, hubIdx[SCENARIOS]["crowdsecurity/barfoo_scenario"].Installed)

}

// Install a collection, disable a scenario.
// Upgrade should install should not enable/download the disabled scenario.
func TestUpgradeConfigInDisabledSceanarioShouldNotBeInstalled(t *testing.T) {
	cfg := envSetup(t)
	defer envTearDown(cfg)

	// fresh install of collection
	getHubIdxOrFail(t)

	require.False(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.False(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.False(t, hubIdx[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)

	require.NoError(t, InstallItem(cfg, "crowdsecurity/test_collection", COLLECTIONS, false, false))

	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)
	require.False(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)
	require.True(t, hubIdx[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	assertCollectionDepsInstalled(t, "crowdsecurity/test_collection")

	RemoveMany(cfg, SCENARIOS, "crowdsecurity/foobar_scenario", false, false, false)
	getHubIdxOrFail(t)
	// scenario referenced by collection  was deleted hence, collection should be tainted
	require.False(t, hubIdx[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)

	if err := UpdateHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to download index : %s", err)
	}

	UpgradeConfig(cfg, COLLECTIONS, "crowdsecurity/test_collection", false)

	getHubIdxOrFail(t)
	require.False(t, hubIdx[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
}

func getHubIdxOrFail(t *testing.T) {
	if err := GetHubIdx(getTestCfg().Hub); err != nil {
		t.Fatalf("failed to load hub index")
	}
}

// Install a collection. Disable a referenced scenario. Publish new version of collection with new scenario
// Upgrade should not enable/download the disabled scenario.
// Upgrade should install and enable the newly added scenario.
func TestUpgradeConfigNewScenarioIsInstalledWhenReferencedScenarioIsDisabled(t *testing.T) {
	cfg := envSetup(t)
	defer envTearDown(cfg)

	// fresh install of collection
	getHubIdxOrFail(t)

	require.False(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.False(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.False(t, hubIdx[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)

	require.NoError(t, InstallItem(cfg, "crowdsecurity/test_collection", COLLECTIONS, false, false))

	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)
	require.False(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)
	require.True(t, hubIdx[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	assertCollectionDepsInstalled(t, "crowdsecurity/test_collection")

	RemoveMany(cfg, SCENARIOS, "crowdsecurity/foobar_scenario", false, false, false)
	getHubIdxOrFail(t)
	// scenario referenced by collection  was deleted hence, collection should be tainted
	require.False(t, hubIdx[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	require.True(t, hubIdx[SCENARIOS]["crowdsecurity/foobar_scenario"].Downloaded) // this fails
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.True(t, hubIdx[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)

	// collection receives an update. It now adds new scenario "crowdsecurity/barfoo_scenario"
	// we now attempt to upgrade the collection, however it shouldn't install the foobar_scenario
	// we just removed. Nor should it install the newly added sceanrio
	pushUpdateToCollectionInHub()

	if err := UpdateHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to download index : %s", err)
	}
	require.False(t, hubIdx[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	getHubIdxOrFail(t)

	UpgradeConfig(cfg, COLLECTIONS, "crowdsecurity/test_collection", false)
	getHubIdxOrFail(t)
	require.False(t, hubIdx[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	require.True(t, hubIdx[SCENARIOS]["crowdsecurity/barfoo_scenario"].Installed)
}

func assertCollectionDepsInstalled(t *testing.T, collection string) {
	t.Helper()
	c := hubIdx[COLLECTIONS][collection]
	require.NoError(t, CollecDepsCheck(&c))
}

func pushUpdateToCollectionInHub() {
	responseByPath["/master/.index.json"] = fileToStringX("./tests/index2.json")
	responseByPath["/master/collections/crowdsecurity/test_collection.yaml"] = fileToStringX("./tests/collection_v2.yaml")
}
