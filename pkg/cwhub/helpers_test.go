package cwhub

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Download index, install collection. Add scenario to collection (hub-side), update index, upgrade collection
// We expect the new scenario to be installed
func TestUpgradeConfigNewScenarioInCollection(t *testing.T) {
	cfg, hub := envSetup(t)
	defer envTearDown(cfg)

	// fresh install of collection
	getHubIdxOrFail(t)

	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)

	require.NoError(t, hub.InstallItem("crowdsecurity/test_collection", COLLECTIONS, false, false))

	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)

	// This is the scenario that gets added in next version of collection
	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/barfoo_scenario"].Downloaded)
	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/barfoo_scenario"].Installed)

	assertCollectionDepsInstalled(t, "crowdsecurity/test_collection")

	// collection receives an update. It now adds new scenario "crowdsecurity/barfoo_scenario"
	pushUpdateToCollectionInHub()

	hub, err := InitHubUpdate(cfg.Hub)
	if err != nil {
		t.Fatalf("failed to download index : %s", err)
	}

	getHubIdxOrFail(t)

	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)

	err = hub.UpgradeConfig(COLLECTIONS, "crowdsecurity/test_collection", false)
	require.NoError(t, err)
	assertCollectionDepsInstalled(t, "crowdsecurity/test_collection")

	require.True(t, hub.Items[SCENARIOS]["crowdsecurity/barfoo_scenario"].Downloaded)
	require.True(t, hub.Items[SCENARIOS]["crowdsecurity/barfoo_scenario"].Installed)
}

// Install a collection, disable a scenario.
// Upgrade should install should not enable/download the disabled scenario.
func TestUpgradeConfigInDisabledScenarioShouldNotBeInstalled(t *testing.T) {
	cfg, hub := envSetup(t)
	defer envTearDown(cfg)

	// fresh install of collection
	getHubIdxOrFail(t)

	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)

	require.NoError(t, hub.InstallItem("crowdsecurity/test_collection", COLLECTIONS, false, false))

	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)
	require.True(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	assertCollectionDepsInstalled(t, "crowdsecurity/test_collection")

	err := hub.RemoveMany(SCENARIOS, "crowdsecurity/foobar_scenario", false, false, false)
	require.NoError(t, err)

	getHubIdxOrFail(t)
	// scenario referenced by collection  was deleted hence, collection should be tainted
	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)

	hub, err = InitHubUpdate(cfg.Hub)
	if err != nil {
		t.Fatalf("failed to download index : %s", err)
	}

	err = hub.UpgradeConfig(COLLECTIONS, "crowdsecurity/test_collection", false)
	require.NoError(t, err)

	getHubIdxOrFail(t)
	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
}

func getHubIdxOrFail(t *testing.T) {
	if _, err := InitHub(getTestCfg().Hub); err != nil {
		t.Fatalf("failed to load hub index")
	}
}

// Install a collection. Disable a referenced scenario. Publish new version of collection with new scenario
// Upgrade should not enable/download the disabled scenario.
// Upgrade should install and enable the newly added scenario.
func TestUpgradeConfigNewScenarioIsInstalledWhenReferencedScenarioIsDisabled(t *testing.T) {
	cfg, hub := envSetup(t)
	defer envTearDown(cfg)

	// fresh install of collection
	getHubIdxOrFail(t)

	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)

	require.NoError(t, hub.InstallItem("crowdsecurity/test_collection", COLLECTIONS, false, false))

	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)
	require.True(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	assertCollectionDepsInstalled(t, "crowdsecurity/test_collection")

	err := hub.RemoveMany(SCENARIOS, "crowdsecurity/foobar_scenario", false, false, false)
	require.NoError(t, err)

	getHubIdxOrFail(t)
	// scenario referenced by collection  was deleted hence, collection should be tainted
	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	require.True(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Downloaded) // this fails
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)

	// collection receives an update. It now adds new scenario "crowdsecurity/barfoo_scenario"
	// we now attempt to upgrade the collection, however it shouldn't install the foobar_scenario
	// we just removed. Nor should it install the newly added scenario
	pushUpdateToCollectionInHub()

	hub, err = InitHubUpdate(cfg.Hub)
	if err != nil {
		t.Fatalf("failed to download index : %s", err)
	}

	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	getHubIdxOrFail(t)

	err = hub.UpgradeConfig(COLLECTIONS, "crowdsecurity/test_collection", false)
	require.NoError(t, err)

	getHubIdxOrFail(t)
	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	require.True(t, hub.Items[SCENARIOS]["crowdsecurity/barfoo_scenario"].Installed)
}

func assertCollectionDepsInstalled(t *testing.T, collection string) {
	t.Helper()

	hub, err := GetHub()
	require.NoError(t, err)

	c := hub.Items[COLLECTIONS][collection]
	require.NoError(t, hub.CollectDepsCheck(&c))
}

func pushUpdateToCollectionInHub() {
	responseByPath["/master/.index.json"] = fileToStringX("./testdata/index2.json")
	responseByPath["/master/collections/crowdsecurity/test_collection.yaml"] = fileToStringX("./testdata/collection_v2.yaml")
}
