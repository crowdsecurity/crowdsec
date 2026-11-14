package cwhub

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// treeIndex describes a collection "author/coll" that pulls in a sub-collection and shares a
// parser with it, plus a standalone parser. It is enough to exercise nesting and dedup.
const treeIndex = `
{
  "parsers": {
    "author/p1":         {"stage": "s01-parse", "path": "parsers/s01-parse/p1.yaml",         "version": "1.0", "versions": {"1.0": {"digest": "x"}}},
    "author/p2":         {"stage": "s01-parse", "path": "parsers/s01-parse/p2.yaml",         "version": "1.0", "versions": {"1.0": {"digest": "x"}}},
    "author/p3":         {"stage": "s01-parse", "path": "parsers/s01-parse/p3.yaml",         "version": "1.0", "versions": {"1.0": {"digest": "x"}}},
    "author/shared":     {"stage": "s01-parse", "path": "parsers/s01-parse/shared.yaml",     "version": "1.0", "versions": {"1.0": {"digest": "x"}}},
    "author/standalone": {"stage": "s01-parse", "path": "parsers/s01-parse/standalone.yaml", "version": "1.0", "versions": {"1.0": {"digest": "x"}}}
  },
  "collections": {
    "author/coll": {
      "path": "collections/coll.yaml", "version": "1.0", "versions": {"1.0": {"digest": "x"}},
      "parsers": ["author/p1", "author/p2", "author/shared"],
      "collections": ["author/subcoll"]
    },
    "author/subcoll": {
      "path": "collections/subcoll.yaml", "version": "1.0", "versions": {"1.0": {"digest": "x"}},
      "parsers": ["author/p3", "author/shared"]
    }
  }
}`

// markInstalled fakes an installed item: a non-empty LocalPath makes IsInstalled() true, UpToDate
// makes CurrentDependencies() read from the index instead of a content file, and parents feed
// InstalledParents().
func markInstalled(hub *Hub, itemType, name string, parents ...string) {
	item := hub.GetItem(itemType, name)
	item.State.LocalPath = "/fake/" + name
	item.State.UpToDate = true
	item.State.BelongsToCollections = parents
}

func TestInstalledItems(t *testing.T) {
	hub, err := testHub(t, treeIndex)
	require.NoError(t, err)

	markInstalled(hub, COLLECTIONS, "author/coll")
	markInstalled(hub, COLLECTIONS, "author/subcoll", "author/coll")
	markInstalled(hub, PARSERS, "author/p1", "author/coll")
	markInstalled(hub, PARSERS, "author/p2", "author/coll")
	markInstalled(hub, PARSERS, "author/p3", "author/subcoll", "author/coll")
	markInstalled(hub, PARSERS, "author/shared", "author/coll", "author/subcoll")
	markInstalled(hub, PARSERS, "author/standalone")

	nodes := hub.InstalledItems()

	// top level: the root collection, then the standalone parser. subcoll has an installed
	// parent so it is not a root; the collection-owned parsers are nested, not top-level.
	require.Len(t, nodes, 2)
	assert.Equal(t, "author/coll", nodes[0].Item.Name)
	assert.Equal(t, "author/standalone", nodes[1].Item.Name)
	assert.Empty(t, nodes[1].Children)

	// count every item in the forest: each installed item must appear exactly once, even a
	// leaf (shared) pulled in by two collections.
	seen := map[string]int{}

	var walk func(n *ItemNode)
	walk = func(n *ItemNode) {
		seen[n.Item.Name]++
		for _, c := range n.Children {
			walk(c)
		}
	}

	for _, n := range nodes {
		walk(n)
	}

	assert.Equal(t, 1, seen["author/shared"], "a shared leaf should appear once")
	assert.Equal(t, 1, seen["author/subcoll"])
	assert.Equal(t, 1, seen["author/p3"])
	assert.Len(t, seen, 7, "every installed item shows once")

	// author/p3 hangs under subcoll, itself under coll
	var subcoll *ItemNode

	for _, c := range nodes[0].Children {
		if c.Item.Name == "author/subcoll" {
			subcoll = c
		}
	}

	require.NotNil(t, subcoll)
	require.Len(t, subcoll.Children, 1)
	assert.Equal(t, "author/p3", subcoll.Children[0].Item.Name)
}
