package cwhub

// ItemNode is an installed item together with its installed sub-items, nested
// recursively. Non-collections and leaf collections have no children.
type ItemNode struct {
	Item     *Item
	Children []*ItemNode
}

// InstalledItems returns the top-level installed items: those pulled in by no
// installed collection. A collection carries its installed sub-items
// (recursively) as children; every other installed item is a childless node.
// Collections come first, then other types; each installed item appears once
// (a leaf shared by several collections is placed under the first one visited).
func (h *Hub) InstalledItems() []*ItemNode {
	seen := make(map[string]bool)

	var build func(item *Item) *ItemNode

	build = func(item *Item) *ItemNode {
		seen[item.FQName()] = true
		node := &ItemNode{Item: item}

		for sub := range item.CurrentDependencies().SubItems(h) {
			if !sub.State.IsInstalled() || seen[sub.FQName()] {
				continue
			}

			if sub.Type == COLLECTIONS {
				node.Children = append(node.Children, build(sub))
				continue
			}

			seen[sub.FQName()] = true
			node.Children = append(node.Children, &ItemNode{Item: sub})
		}

		return node
	}

	ret := make([]*ItemNode, 0)

	// collections are the roots of the tree
	for _, item := range h.GetInstalledByType(COLLECTIONS, true) {
		if len(item.InstalledParents()) == 0 {
			ret = append(ret, build(item))
		}
	}

	// standalone items: installed, part of no installed collection, not already nested
	for _, itemType := range ItemTypes {
		if itemType == COLLECTIONS {
			continue
		}

		for _, item := range h.GetInstalledByType(itemType, true) {
			if len(item.InstalledParents()) == 0 && !seen[item.FQName()] {
				ret = append(ret, &ItemNode{Item: item})
			}
		}
	}

	return ret
}
