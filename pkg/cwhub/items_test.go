package cwhub

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestItemStatus(t *testing.T) {
	hub := envSetup(t)

	// get existing map
	x := hub.GetItemMap(COLLECTIONS)
	require.NotEmpty(t, x)

	// Get item : good and bad
	for k := range x {
		item := hub.GetItem(COLLECTIONS, k)
		require.NotNil(t, item)

		item.Installed = true
		item.UpToDate = false
		item.Local = false
		item.Tainted = false

		txt, _ := item.Status()
		require.Equal(t, "enabled,update-available", txt)

		item.Installed = false
		item.UpToDate = false
		item.Local = true
		item.Tainted = false

		txt, _ = item.Status()
		require.Equal(t, "disabled,local", txt)
	}

	stats := hub.ItemStats()
	require.Equal(t, []string{"Loaded: 2 parsers, 1 scenarios, 3 collections"}, stats)
}

func TestGetters(t *testing.T) {
	hub := envSetup(t)

	// get non existing map
	empty := hub.GetItemMap("ratata")
	require.Nil(t, empty)

	// get existing map
	x := hub.GetItemMap(COLLECTIONS)
	require.NotEmpty(t, x)

	// Get item : good and bad
	for k := range x {
		empty := hub.GetItem(COLLECTIONS, k+"nope")
		require.Nil(t, empty)

		item := hub.GetItem(COLLECTIONS, k)
		require.NotNil(t, item)

		// Add item and get it
		item.Name += "nope"
		err := hub.AddItem(*item)
		require.NoError(t, err)

		newitem := hub.GetItem(COLLECTIONS, item.Name)
		require.NotNil(t, newitem)

		item.Type = "ratata"
		err = hub.AddItem(*item)
		cstest.RequireErrorContains(t, err, "ItemType ratata is unknown")
	}
}
