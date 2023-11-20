package cwhub

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type Hub struct {
	Items    HubItems
	local    *csconfig.LocalHubCfg
	remote   *RemoteHubCfg
	Warnings []string
}

func (h *Hub) GetDataDir() string {
	return h.local.InstallDataDir
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

	hub := &Hub{
		local:  local,
		remote: remote,
	}

	if err := hub.parseIndex(); err != nil {
		return nil, fmt.Errorf("failed to load index: %w", err)
	}

	if err := hub.localSync(); err != nil {
		return nil, fmt.Errorf("failed to sync items: %w", err)
	}

	return hub, nil
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
			item.hub = h
			item.Name = name

			// if the item has no (redundant) author, take it from the json key
			if item.Author == "" && strings.Contains(name, "/") {
				item.Author = strings.Split(name, "/")[0]
			}

			item.Type = itemType
			item.FileName = path.Base(item.RemotePath)

			item.logMissingSubItems()
		}
	}

	return nil
}

// ItemStats returns total counts of the hub items
func (h *Hub) ItemStats() []string {
	loaded := ""
	local := 0
	tainted := 0

	for _, itemType := range ItemTypes {
		if len(h.Items[itemType]) == 0 {
			continue
		}

		loaded += fmt.Sprintf("%d %s, ", len(h.Items[itemType]), itemType)

		for _, item := range h.Items[itemType] {
			if item.IsLocal() {
				local++
			}

			if item.Tainted {
				tainted++
			}
		}
	}

	loaded = strings.Trim(loaded, ", ")
	if loaded == "" {
		loaded = "0 items"
	}

	ret := []string{
		fmt.Sprintf("Loaded: %s", loaded),
	}

	if local > 0 || tainted > 0 {
		ret = append(ret, fmt.Sprintf("Unmanaged items: %d local, %d tainted", local, tainted))
	}

	return ret
}
