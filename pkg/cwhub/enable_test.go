package cwhub

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testInstall(hub *Hub, t *testing.T, item Item) {
	// Install the parser
	err := item.downloadLatest(false, false)
	require.NoError(t, err, "failed to download %s", item.Name)

	err = hub.localSync()
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, hub.Items[item.Type][item.Name].UpToDate, "%s should be up-to-date", item.Name)
	assert.False(t, hub.Items[item.Type][item.Name].Installed, "%s should not be installed", item.Name)
	assert.False(t, hub.Items[item.Type][item.Name].Tainted, "%s should not be tainted", item.Name)

	err = item.enable()
	require.NoError(t, err, "failed to enable %s", item.Name)

	err = hub.localSync()
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, hub.Items[item.Type][item.Name].Installed, "%s should be installed", item.Name)
}

func testTaint(hub *Hub, t *testing.T, item Item) {
	assert.False(t, hub.Items[item.Type][item.Name].Tainted, "%s should not be tainted", item.Name)

	f, err := os.OpenFile(item.LocalPath, os.O_APPEND|os.O_WRONLY, 0600)
	require.NoError(t, err, "failed to open %s (%s)", item.LocalPath, item.Name)

	defer f.Close()

	_, err = f.WriteString("tainted")
	require.NoError(t, err, "failed to write to %s (%s)", item.LocalPath, item.Name)

	// Local sync and check status
	err = hub.localSync()
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, hub.Items[item.Type][item.Name].Tainted, "%s should be tainted", item.Name)
}

func testUpdate(hub *Hub, t *testing.T, item Item) {
	assert.False(t, hub.Items[item.Type][item.Name].UpToDate, "%s should not be up-to-date", item.Name)

	// Update it + check status
	err := hub.downloadLatest(&item, true, true)
	require.NoError(t, err, "failed to update %s", item.Name)

	// Local sync and check status
	err = hub.localSync()
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, hub.Items[item.Type][item.Name].UpToDate, "%s should be up-to-date", item.Name)
	assert.False(t, hub.Items[item.Type][item.Name].Tainted, "%s should not be tainted anymore", item.Name)
}

func testDisable(hub *Hub, t *testing.T, item Item) {
	assert.True(t, hub.Items[item.Type][item.Name].Installed, "%s should be installed", item.Name)

	// Remove
	err := item.disable(false, false)
	require.NoError(t, err, "failed to disable %s", item.Name)

	// Local sync and check status
	err = hub.localSync()
	require.NoError(t, err, "failed to run localSync")
	require.Empty(t, hub.Warnings)

	assert.False(t, hub.Items[item.Type][item.Name].Tainted, "%s should not be tainted anymore", item.Name)
	assert.False(t, hub.Items[item.Type][item.Name].Installed, "%s should not be installed anymore", item.Name)
	assert.True(t, hub.Items[item.Type][item.Name].Downloaded, "%s should still be downloaded", item.Name)

	// Purge
	err = item.disable(true, false)
	require.NoError(t, err, "failed to purge %s", item.Name)

	// Local sync and check status
	err = hub.localSync()
	require.NoError(t, err, "failed to run localSync")
	require.Empty(t, hub.Warnings)

	assert.False(t, hub.Items[item.Type][item.Name].Installed, "%s should not be installed anymore", item.Name)
	assert.False(t, hub.Items[item.Type][item.Name].Downloaded, "%s should not be downloaded", item.Name)
}

func TestInstallParser(t *testing.T) {
	/*
	 - install a random parser
	 - check its status
	 - taint it
	 - check its status
	 - force update it
	 - check its status
	 - remove it
	*/
	hub := envSetup(t)

	// map iteration is random by itself
	for _, it := range hub.Items[PARSERS] {
		testInstall(hub, t, it)
		it = hub.Items[PARSERS][it.Name]
		testTaint(hub, t, it)
		it = hub.Items[PARSERS][it.Name]
		testUpdate(hub, t, it)
		it = hub.Items[PARSERS][it.Name]
		testDisable(hub, t, it)

		break
	}
}

func TestInstallCollection(t *testing.T) {
	/*
	 - install a random parser
	 - check its status
	 - taint it
	 - check its status
	 - force update it
	 - check its status
	 - remove it
	*/
	hub := envSetup(t)

	// map iteration is random by itself
	for _, it := range hub.Items[COLLECTIONS] {
		testInstall(hub, t, it)
		it = hub.Items[COLLECTIONS][it.Name]
		testTaint(hub, t, it)
		it = hub.Items[COLLECTIONS][it.Name]
		testUpdate(hub, t, it)
		it = hub.Items[COLLECTIONS][it.Name]
		testDisable(hub, t, it)

		break
	}
}
