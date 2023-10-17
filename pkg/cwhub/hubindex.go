package cwhub

import (
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)


const (
	HubIndexFile = ".index.json"

	// managed item types
	COLLECTIONS   = "collections"
	PARSERS       = "parsers"
	POSTOVERFLOWS = "postoverflows"
	SCENARIOS     = "scenarios"
)

var (
	// XXX: The order is important, as it is used to construct the
	//      index tree in memory --> collections must be last
	ItemTypes = []string{PARSERS, POSTOVERFLOWS, SCENARIOS, COLLECTIONS}
	hubIdx    = HubIndex{}
)


type HubItems map[string]map[string]Item

type HubIndex struct {
	Items HubItems
	skippedLocal   int
	skippedTainted int
}

// displaySummary prints a total count of the hub items
func (h HubIndex) displaySummary() {
	msg := "Loaded: "
	for itemType := range h.Items {
		msg += fmt.Sprintf("%d %s, ", len(h.Items[itemType]), itemType)
	}
	log.Info(strings.Trim(msg, ", "))

	if h.skippedLocal > 0 || h.skippedTainted > 0 {
		log.Infof("unmanaged items: %d local, %d tainted", h.skippedLocal, h.skippedTainted)
	}
}

// DisplaySummary prints a total count of the hub items.
// It is a wrapper around HubIndex.displaySummary() to avoid exporting the hub singleton
func DisplaySummary() {
	hubIdx.displaySummary()
}

// ParseIndex takes the content of a .index.json file and returns the map of associated parsers/scenarios/collections
func ParseIndex(buff []byte) (HubItems, error) {
	var (
		RawIndex     HubItems
		missingItems []string
	)

	if err := json.Unmarshal(buff, &RawIndex); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index: %w", err)
	}

	log.Debugf("%d item types in hub index", len(ItemTypes))

	// Iterate over the different types to complete the struct
	for _, itemType := range ItemTypes {
		log.Tracef("%s: %d items", itemType, len(RawIndex[itemType]))

		for name, item := range RawIndex[itemType] {
			item.Name = name
			item.Type = itemType
			x := strings.Split(item.RemotePath, "/")
			item.FileName = x[len(x)-1]
			RawIndex[itemType][name] = item

			if itemType != COLLECTIONS {
				continue
			}

			// if it's a collection, check its sub-items are present
			// XXX should be done later
			for idx, ptr := range [][]string{item.Parsers, item.PostOverflows, item.Scenarios, item.Collections} {
				ptrtype := ItemTypes[idx]
				for _, p := range ptr {
					if _, ok := RawIndex[ptrtype][p]; !ok {
						log.Errorf("Referred %s %s in collection %s doesn't exist.", ptrtype, p, item.Name)
						missingItems = append(missingItems, p)
					}
				}
			}
		}
	}

	if len(missingItems) > 0 {
		return RawIndex, fmt.Errorf("%q: %w", missingItems, ErrMissingReference)
	}

	return RawIndex, nil
}
