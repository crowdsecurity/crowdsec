package cwhub

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

// Hub is the main structure for the package.
type Hub struct {
	Items    HubItems // Items read from HubDir and InstallDir
	local    *csconfig.LocalHubCfg
	remote   *RemoteHubCfg
	Warnings []string // Warnings encountered during sync
}

// GetDataDir returns the data directory, where data sets are installed.
func (h *Hub) GetDataDir() string {
	return h.local.InstallDataDir
}

// NewHub returns a new Hub instance with local and (optionally) remote configuration, and syncs the local state.
// If updateIndex is true, the local index file is updated from the remote before reading the state of the items.
// All download operations (including updateIndex) return ErrNilRemoteHub if the remote configuration is not set.
func NewHub(local *csconfig.LocalHubCfg, remote *RemoteHubCfg, updateIndex bool) (*Hub, error) {
	if local == nil {
		return nil, fmt.Errorf("no hub configuration found")
	}

	hub := &Hub{
		local:  local,
		remote: remote,
	}

	if updateIndex {
		if err := hub.updateIndex(); err != nil {
			return nil, err
		}
	}

	log.Debugf("loading hub idx %s", local.HubIndexFile)

	if err := hub.parseIndex(); err != nil {
		return nil, fmt.Errorf("failed to load index: %w", err)
	}

	if err := hub.localSync(); err != nil {
		return nil, fmt.Errorf("failed to sync items: %w", err)
	}

	return hub, nil
}

// parseIndex takes the content of an index file and fills the map of associated parsers/scenarios/collections.
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

// ItemStats returns total counts of the hub items, including local and tainted.
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

			if item.State.Tainted {
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

// updateIndex downloads the latest version of the index and writes it to disk if it changed.
func (h *Hub) updateIndex() error {
	body, err := h.remote.fetchIndex()
	if err != nil {
		return err
	}

	oldContent, err := os.ReadFile(h.local.HubIndexFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warningf("failed to read hub index: %s", err)
		}
	} else if bytes.Equal(body, oldContent) {
		log.Info("hub index is up to date")
		return nil
	}

	if err = os.WriteFile(h.local.HubIndexFile, body, 0o644); err != nil {
		return fmt.Errorf("failed to write hub index: %w", err)
	}

	log.Infof("Wrote index to %s, %d bytes", h.local.HubIndexFile, len(body))

	return nil
}

// GetItemMap returns the map of items for a given type.
func (h *Hub) GetItemMap(itemType string) map[string]*Item {
	return h.Items[itemType]
}

// GetItem returns an item from hub based on its type and full name (author/name).
func (h *Hub) GetItem(itemType string, itemName string) *Item {
	return h.GetItemMap(itemType)[itemName]
}

// GetItemNames returns a slice of (full) item names for a given type
// (eg. for collections: crowdsecurity/apache2 crowdsecurity/nginx).
func (h *Hub) GetItemNames(itemType string) []string {
	m := h.GetItemMap(itemType)
	if m == nil {
		return nil
	}

	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}

	return names
}

// GetAllItems returns a slice of all the items of a given type, installed or not.
func (h *Hub) GetAllItems(itemType string) ([]*Item, error) {
	items, ok := h.Items[itemType]
	if !ok {
		return nil, fmt.Errorf("no %s in the hub index", itemType)
	}

	ret := make([]*Item, len(items))

	idx := 0

	for _, item := range items {
		ret[idx] = item
		idx++
	}

	return ret, nil
}

// GetInstalledItems returns a slice of the installed items of a given type.
func (h *Hub) GetInstalledItems(itemType string) ([]*Item, error) {
	items, ok := h.Items[itemType]
	if !ok {
		return nil, fmt.Errorf("no %s in the hub index", itemType)
	}

	retItems := make([]*Item, 0)

	for _, item := range items {
		if item.State.Installed {
			retItems = append(retItems, item)
		}
	}

	return retItems, nil
}

// GetInstalledItemNames returns the names of the installed items of a given type.
func (h *Hub) GetInstalledItemNames(itemType string) ([]string, error) {
	items, err := h.GetInstalledItems(itemType)
	if err != nil {
		return nil, err
	}

	retStr := make([]string, len(items))

	for idx, it := range items {
		retStr[idx] = it.Name
	}

	return retStr, nil
}
