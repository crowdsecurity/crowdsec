package cwhub

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type Hub struct {
	Items          HubItems
	local          *csconfig.LocalHubCfg
	remote         *RemoteHubCfg
	skippedLocal   int
	skippedTainted int
	Warnings       []string
}

var theHub *Hub

// GetHub returns the hub singleton
// it returns an error if it's not initialized to avoid nil dereference
// XXX: convenience function that we should get rid of at some point
func GetHub() (*Hub, error) {
	if theHub == nil {
		return nil, fmt.Errorf("hub not initialized")
	}

	return theHub, nil
}

// NewHub returns a new Hub instance with local and (optionally) remote configuration, and syncs the local state
// It also downloads the index if downloadIndex is true
func NewHub(local *csconfig.LocalHubCfg, remote *RemoteHubCfg, downloadIndex bool) (*Hub, error) {
	if local == nil {
		return nil, fmt.Errorf("no hub configuration found")
	}

	if downloadIndex {
		if err := remote.downloadIndex(local.HubIndexFile); err != nil {
			return nil, err
		}
	}

	log.Debugf("loading hub idx %s", local.HubIndexFile)

	theHub = &Hub{
		local:  local,
		remote: remote,
	}

	if err := theHub.parseIndex(); err != nil {
		return nil, fmt.Errorf("failed to load index: %w", err)
	}

	if err := theHub.localSync(); err != nil {
		return nil, fmt.Errorf("failed to sync items: %w", err)
	}

	return theHub, nil
}

// parseIndex takes the content of an index file and fills the map of associated parsers/scenarios/collections
func (h *Hub) parseIndex() error {
	bidx, err := os.ReadFile(h.local.HubIndexFile)
	if err != nil {
		return fmt.Errorf("unable to read index file: %w", err)
	}

	if err := json.Unmarshal(bidx, &h.Items); err != nil {
		return fmt.Errorf("failed to unmarshal index: %w", err)
	}

	log.Debugf("%d item types in hub index", len(ItemTypes))

	// Iterate over the different types to complete the struct
	for _, itemType := range ItemTypes {
		log.Tracef("%s: %d items", itemType, len(h.Items[itemType]))

		for name, item := range h.Items[itemType] {
			item.Name = name

			// if the item has no (redundant) author, take it from the json key
			if item.Author == "" && strings.Contains(name, "/") {
				item.Author = strings.Split(name, "/")[0]
			}

			item.Type = itemType
			x := strings.Split(item.RemotePath, "/")
			item.FileName = x[len(x)-1]
			h.Items[itemType][name] = item

			// if it's a collection, check its sub-items are present
			// XXX should be done later, maybe report all missing at once?
			for _, sub := range item.SubItems() {
				if _, ok := h.Items[sub.Type][sub.Name]; !ok {
					log.Errorf("Referred %s %s in collection %s doesn't exist.", sub.Type, sub.Name, item.Name)
				}
			}
		}
	}

	return nil
}

// ItemStats returns total counts of the hub items
func (h *Hub) ItemStats() []string {
	loaded := ""

	for _, itemType := range ItemTypes {
		if len(h.Items[itemType]) == 0 {
			continue
		}

		loaded += fmt.Sprintf("%d %s, ", len(h.Items[itemType]), itemType)
	}

	loaded = strings.Trim(loaded, ", ")
	if loaded == "" {
		// empty hub
		loaded = "0 items"
	}

	ret := []string{
		fmt.Sprintf("Loaded: %s", loaded),
	}

	if h.skippedLocal > 0 || h.skippedTainted > 0 {
		ret = append(ret, fmt.Sprintf("Unmanaged items: %d local, %d tainted", h.skippedLocal, h.skippedTainted))
	}

	return ret
}
