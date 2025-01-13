package cwhub

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestItemStats(t *testing.T) {
	hub := envSetup(t)

	// get existing map
	x := hub.GetItemMap(COLLECTIONS)
	require.NotEmpty(t, x)

	stats := hub.ItemStats()
	require.Equal(t, []string{
		"Loaded: 2 parsers, 1 scenarios, 3 collections",
	}, stats)
}

func TestGetters(t *testing.T) {
	hub := envSetup(t)

	// get non existing map
	empty := hub.GetItemMap("ratata")
	require.Nil(t, empty)

	// get existing map
	x := hub.GetItemMap(COLLECTIONS)
	require.NotEmpty(t, x)

	// Get item: good and bad
	for k := range x {
		empty := hub.GetItem(COLLECTIONS, k+"nope")
		require.Nil(t, empty)

		item := hub.GetItem(COLLECTIONS, k)
		require.NotNil(t, item)

		// Add item and get it
		item.Name += "nope"
		hub.addItem(item)

		newitem := hub.GetItem(COLLECTIONS, item.Name)
		require.NotNil(t, newitem)
	}
}
