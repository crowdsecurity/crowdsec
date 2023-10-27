package cwhub

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

// Download index, install collection. Add scenario to collection (hub-side), update index, upgrade collection
// We expect the new scenario to be installed
func TestUpgradeItemNewScenarioInCollection(t *testing.T) {
	hub := envSetup(t)

	// fresh install of collection
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)

	require.NoError(t, hub.InstallItem("crowdsecurity/test_collection", COLLECTIONS, false, false, mockURLTemplate, "master"))

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

	hub, err := InitHubUpdate(hub.cfg, mockURLTemplate, "master", ".index.json")
	require.NoError(t, err, "failed to download index: %s", err)

	hub = getHubOrFail(t, hub.cfg)

	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)

	didUpdate, err := hub.UpgradeItem(COLLECTIONS, "crowdsecurity/test_collection", false, mockURLTemplate, "master")
	require.NoError(t, err)
	require.True(t, didUpdate)
	assertCollectionDepsInstalled(t, "crowdsecurity/test_collection")

	require.True(t, hub.Items[SCENARIOS]["crowdsecurity/barfoo_scenario"].Downloaded)
	require.True(t, hub.Items[SCENARIOS]["crowdsecurity/barfoo_scenario"].Installed)
}

// Install a collection, disable a scenario.
// Upgrade should install should not enable/download the disabled scenario.
func TestUpgradeItemInDisabledScenarioShouldNotBeInstalled(t *testing.T) {
	hub := envSetup(t)

	// fresh install of collection
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)

	require.NoError(t, hub.InstallItem("crowdsecurity/test_collection", COLLECTIONS, false, false, mockURLTemplate, "master"))

	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)
	require.True(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	assertCollectionDepsInstalled(t, "crowdsecurity/test_collection")

	err := hub.RemoveMany(SCENARIOS, "crowdsecurity/foobar_scenario", false, false, false)
	require.NoError(t, err)

	hub = getHubOrFail(t, hub.cfg)
	// scenario referenced by collection  was deleted hence, collection should be tainted
	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)

	hub, err = InitHubUpdate(hub.cfg, mockURLTemplate, "master", ".index.json")
	require.NoError(t, err, "failed to download index: %s", err)

	didUpdate, err := hub.UpgradeItem(COLLECTIONS, "crowdsecurity/test_collection", false, mockURLTemplate, "master")
	require.NoError(t, err)
	require.True(t, didUpdate)

	hub = getHubOrFail(t, hub.cfg)
	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
}

// getHubOrFail refreshes the hub state (load index, sync) and returns the singleton, or fails the test
func getHubOrFail(t *testing.T, hubCfg *csconfig.HubCfg) *Hub {
	hub, err := InitHub(hubCfg)
	require.NoError(t, err, "failed to load hub index")

	return hub
}

// Install a collection. Disable a referenced scenario. Publish new version of collection with new scenario
// Upgrade should not enable/download the disabled scenario.
// Upgrade should install and enable the newly added scenario.
func TestUpgradeItemNewScenarioIsInstalledWhenReferencedScenarioIsDisabled(t *testing.T) {
	hub := envSetup(t)

	// fresh install of collection
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)

	require.NoError(t, hub.InstallItem("crowdsecurity/test_collection", COLLECTIONS, false, false, mockURLTemplate, "master"))

	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Downloaded)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Installed)
	require.True(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].UpToDate)
	require.False(t, hub.Items[COLLECTIONS]["crowdsecurity/test_collection"].Tainted)
	require.True(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	assertCollectionDepsInstalled(t, "crowdsecurity/test_collection")

	err := hub.RemoveMany(SCENARIOS, "crowdsecurity/foobar_scenario", false, false, false)
	require.NoError(t, err)

	hub = getHubOrFail(t, hub.cfg)
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

	hub, err = InitHubUpdate(hub.cfg, mockURLTemplate, "master", ".index.json")
	require.NoError(t, err, "failed to download index: %s", err)

	require.False(t, hub.Items[SCENARIOS]["crowdsecurity/foobar_scenario"].Installed)
	hub = getHubOrFail(t, hub.cfg)

	didUpdate, err := hub.UpgradeItem(COLLECTIONS, "crowdsecurity/test_collection", false, mockURLTemplate, "master")
	require.NoError(t, err)
	require.True(t, didUpdate)

	hub = getHubOrFail(t, hub.cfg)
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
