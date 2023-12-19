package cwhub

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

// Download index, install collection. Add scenario to collection (hub-side), update index, upgrade collection.
// We expect the new scenario to be installed.
func TestUpgradeItemNewScenarioInCollection(t *testing.T) {
	hub := envSetup(t)

	item := hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection")

	// fresh install of collection
	require.False(t, item.State.Downloaded)
	require.False(t, item.State.Installed)

	require.NoError(t, item.Install(false, false))

	require.True(t, item.State.Downloaded)
	require.True(t, item.State.Installed)
	require.True(t, item.State.UpToDate)
	require.False(t, item.State.Tainted)

	// This is the scenario that gets added in next version of collection
	require.Nil(t, hub.GetItem(SCENARIOS, "crowdsecurity/barfoo_scenario"))

	assertCollectionDepsInstalled(t, hub, "crowdsecurity/test_collection")

	// collection receives an update. It now adds new scenario "crowdsecurity/barfoo_scenario"
	pushUpdateToCollectionInHub()

	remote := &RemoteHubCfg{
		URLTemplate: mockURLTemplate,
		Branch:      "master",
		IndexPath:   ".index.json",
	}

	hub, err := NewHub(hub.local, remote, true, nil)
	require.NoError(t, err, "failed to download index: %s", err)

	hub = getHubOrFail(t, hub.local, remote)

	item = hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection")

	require.True(t, item.State.Downloaded)
	require.True(t, item.State.Installed)
	require.False(t, item.State.UpToDate)
	require.False(t, item.State.Tainted)

	didUpdate, err := item.Upgrade(false)
	require.NoError(t, err)
	require.True(t, didUpdate)
	assertCollectionDepsInstalled(t, hub, "crowdsecurity/test_collection")

	require.True(t, hub.GetItem(SCENARIOS, "crowdsecurity/barfoo_scenario").State.Downloaded)
	require.True(t, hub.GetItem(SCENARIOS, "crowdsecurity/barfoo_scenario").State.Installed)
}

// Install a collection, disable a scenario.
// Upgrade should install should not enable/download the disabled scenario.
func TestUpgradeItemInDisabledScenarioShouldNotBeInstalled(t *testing.T) {
	hub := envSetup(t)

	item := hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection")

	// fresh install of collection
	require.False(t, item.State.Downloaded)
	require.False(t, item.State.Installed)
	require.False(t, hub.GetItem(SCENARIOS, "crowdsecurity/foobar_scenario").State.Installed)

	require.NoError(t, item.Install(false, false))

	require.True(t, item.State.Downloaded)
	require.True(t, item.State.Installed)
	require.True(t, item.State.UpToDate)
	require.False(t, item.State.Tainted)
	require.True(t, hub.GetItem(SCENARIOS, "crowdsecurity/foobar_scenario").State.Installed)
	assertCollectionDepsInstalled(t, hub, "crowdsecurity/test_collection")

	item = hub.GetItem(SCENARIOS, "crowdsecurity/foobar_scenario")
	didRemove, err := item.Remove(false, false)
	require.NoError(t, err)
	require.True(t, didRemove)

	remote := &RemoteHubCfg{
		URLTemplate: mockURLTemplate,
		Branch:      "master",
		IndexPath:   ".index.json",
	}

	hub = getHubOrFail(t, hub.local, remote)
	// scenario referenced by collection  was deleted hence, collection should be tainted
	require.False(t, hub.GetItem(SCENARIOS, "crowdsecurity/foobar_scenario").State.Installed)

	require.True(t, hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection").State.Tainted)
	require.True(t, hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection").State.Downloaded)
	require.True(t, hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection").State.Installed)
	require.True(t, hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection").State.UpToDate)

	hub, err = NewHub(hub.local, remote, true, nil)
	require.NoError(t, err, "failed to download index: %s", err)

	item = hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection")
	didUpdate, err := item.Upgrade(false)
	require.NoError(t, err)
	require.False(t, didUpdate)

	hub = getHubOrFail(t, hub.local, remote)
	require.False(t, hub.GetItem(SCENARIOS, "crowdsecurity/foobar_scenario").State.Installed)
}

// getHubOrFail refreshes the hub state (load index, sync) and returns the singleton, or fails the test.
func getHubOrFail(t *testing.T, local *csconfig.LocalHubCfg, remote *RemoteHubCfg) *Hub {
	hub, err := NewHub(local, remote, false, nil)
	require.NoError(t, err, "failed to load hub index")

	return hub
}

// Install a collection. Disable a referenced scenario. Publish new version of collection with new scenario
// Upgrade should not enable/download the disabled scenario.
// Upgrade should install and enable the newly added scenario.
func TestUpgradeItemNewScenarioIsInstalledWhenReferencedScenarioIsDisabled(t *testing.T) {
	hub := envSetup(t)

	item := hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection")

	// fresh install of collection
	require.False(t, item.State.Downloaded)
	require.False(t, item.State.Installed)
	require.False(t, hub.GetItem(SCENARIOS, "crowdsecurity/foobar_scenario").State.Installed)

	require.NoError(t, item.Install(false, false))

	require.True(t, item.State.Downloaded)
	require.True(t, item.State.Installed)
	require.True(t, item.State.UpToDate)
	require.False(t, item.State.Tainted)
	require.True(t, hub.GetItem(SCENARIOS, "crowdsecurity/foobar_scenario").State.Installed)
	assertCollectionDepsInstalled(t, hub, "crowdsecurity/test_collection")

	item = hub.GetItem(SCENARIOS, "crowdsecurity/foobar_scenario")
	didRemove, err := item.Remove(false, false)
	require.NoError(t, err)
	require.True(t, didRemove)

	remote := &RemoteHubCfg{
		URLTemplate: mockURLTemplate,
		Branch:      "master",
		IndexPath:   ".index.json",
	}

	hub = getHubOrFail(t, hub.local, remote)
	// scenario referenced by collection  was deleted hence, collection should be tainted
	require.False(t, hub.GetItem(SCENARIOS, "crowdsecurity/foobar_scenario").State.Installed)
	require.True(t, hub.GetItem(SCENARIOS, "crowdsecurity/foobar_scenario").State.Downloaded) // this fails
	require.True(t, hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection").State.Tainted)
	require.True(t, hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection").State.Downloaded)
	require.True(t, hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection").State.Installed)
	require.True(t, hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection").State.UpToDate)

	// collection receives an update. It now adds new scenario "crowdsecurity/barfoo_scenario"
	// we now attempt to upgrade the collection, however it shouldn't install the foobar_scenario
	// we just removed. Nor should it install the newly added scenario
	pushUpdateToCollectionInHub()

	hub, err = NewHub(hub.local, remote, true, nil)
	require.NoError(t, err, "failed to download index: %s", err)

	require.False(t, hub.GetItem(SCENARIOS, "crowdsecurity/foobar_scenario").State.Installed)
	hub = getHubOrFail(t, hub.local, remote)

	item = hub.GetItem(COLLECTIONS, "crowdsecurity/test_collection")
	didUpdate, err := item.Upgrade(false)
	require.NoError(t, err)
	require.True(t, didUpdate)

	hub = getHubOrFail(t, hub.local, remote)
	require.False(t, hub.GetItem(SCENARIOS, "crowdsecurity/foobar_scenario").State.Installed)
	require.True(t, hub.GetItem(SCENARIOS, "crowdsecurity/barfoo_scenario").State.Installed)
}

func assertCollectionDepsInstalled(t *testing.T, hub *Hub, collection string) {
	t.Helper()

	c := hub.GetItem(COLLECTIONS, collection)
	require.Empty(t, c.checkSubItemVersions())
}

func pushUpdateToCollectionInHub() {
	responseByPath["/master/.index.json"] = fileToStringX("./testdata/index2.json")
	responseByPath["/master/collections/crowdsecurity/test_collection.yaml"] = fileToStringX("./testdata/collection_v2.yaml")
}
