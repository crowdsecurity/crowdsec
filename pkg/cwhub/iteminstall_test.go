package cwhub

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testInstall(hub *Hub, t *testing.T, item *Item) {
	// Install the parser
	_, err := item.downloadLatest(false, false)
	require.NoError(t, err, "failed to download %s", item.Name)

	err = hub.localSync()
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, item.State.UpToDate, "%s should be up-to-date", item.Name)
	assert.False(t, item.State.Installed, "%s should not be installed", item.Name)
	assert.False(t, item.State.Tainted, "%s should not be tainted", item.Name)

	err = item.enable()
	require.NoError(t, err, "failed to enable %s", item.Name)

	err = hub.localSync()
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, item.State.Installed, "%s should be installed", item.Name)
}

func testTaint(hub *Hub, t *testing.T, item *Item) {
	assert.False(t, item.State.Tainted, "%s should not be tainted", item.Name)

	// truncate the file
	f, err := os.Create(item.State.LocalPath)
	require.NoError(t, err)
	f.Close()

	// Local sync and check status
	err = hub.localSync()
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, item.State.Tainted, "%s should be tainted", item.Name)
}

func testUpdate(hub *Hub, t *testing.T, item *Item) {
	assert.False(t, item.State.UpToDate, "%s should not be up-to-date", item.Name)

	// Update it + check status
	_, err := item.downloadLatest(true, true)
	require.NoError(t, err, "failed to update %s", item.Name)

	// Local sync and check status
	err = hub.localSync()
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, item.State.UpToDate, "%s should be up-to-date", item.Name)
	assert.False(t, item.State.Tainted, "%s should not be tainted anymore", item.Name)
}

func testDisable(hub *Hub, t *testing.T, item *Item) {
	assert.True(t, item.State.Installed, "%s should be installed", item.Name)

	// Remove
	_, err := item.disable(false, false)
	require.NoError(t, err, "failed to disable %s", item.Name)

	// Local sync and check status
	err = hub.localSync()
	require.NoError(t, err, "failed to run localSync")
	require.Empty(t, hub.Warnings)

	assert.False(t, item.State.Tainted, "%s should not be tainted anymore", item.Name)
	assert.False(t, item.State.Installed, "%s should not be installed anymore", item.Name)
	assert.True(t, item.State.Downloaded, "%s should still be downloaded", item.Name)

	// Purge
	_, err = item.disable(true, false)
	require.NoError(t, err, "failed to purge %s", item.Name)

	// Local sync and check status
	err = hub.localSync()
	require.NoError(t, err, "failed to run localSync")
	require.Empty(t, hub.Warnings)

	assert.False(t, item.State.Installed, "%s should not be installed anymore", item.Name)
	assert.False(t, item.State.Downloaded, "%s should not be downloaded", item.Name)
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
	for _, it := range hub.GetItemMap(PARSERS) {
		testInstall(hub, t, it)
		testTaint(hub, t, it)
		testUpdate(hub, t, it)
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
	for _, it := range hub.GetItemMap(COLLECTIONS) {
		testInstall(hub, t, it)
		testTaint(hub, t, it)
		testUpdate(hub, t, it)
		testDisable(hub, t, it)

		break
	}
}
