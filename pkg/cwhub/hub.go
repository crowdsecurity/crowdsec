package cwhub

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/sirupsen/logrus"
	"slices"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

// Hub is the main structure for the package.
type Hub struct {
	items    HubItems // Items read from HubDir and InstallDir
	local    *csconfig.LocalHubCfg
	remote   *RemoteHubCfg
	Warnings []string // Warnings encountered during sync
	logger   *logrus.Logger
}

// GetDataDir returns the data directory, where data sets are installed.
func (h *Hub) GetDataDir() string {
	return h.local.InstallDataDir
}

// NewHub returns a new Hub instance with local and (optionally) remote configuration, and syncs the local state.
// If updateIndex is true, the local index file is updated from the remote before reading the state of the items.
// All download operations (including updateIndex) return ErrNilRemoteHub if the remote configuration is not set.
func NewHub(local *csconfig.LocalHubCfg, remote *RemoteHubCfg, updateIndex bool, logger *logrus.Logger) (*Hub, error) {
	if local == nil {
		return nil, fmt.Errorf("no hub configuration found")
	}

	if logger == nil {
		logger = logrus.New()
		logger.SetOutput(io.Discard)
	}

	hub := &Hub{
		local:  local,
		remote: remote,
		logger: logger,
	}

	if updateIndex {
		if err := hub.updateIndex(); err != nil {
			return nil, err
		}
	}

	logger.Debugf("loading hub idx %s", local.HubIndexFile)

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

	if err := json.Unmarshal(bidx, &h.items); err != nil {
		return fmt.Errorf("failed to unmarshal index: %w", err)
	}

	h.logger.Debugf("%d item types in hub index", len(ItemTypes))

	// Iterate over the different types to complete the struct
	for _, itemType := range ItemTypes {
		h.logger.Tracef("%s: %d items", itemType, len(h.GetItemMap(itemType)))

		for name, item := range h.GetItemMap(itemType) {
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
		if len(h.GetItemMap(itemType)) == 0 {
			continue
		}

		loaded += fmt.Sprintf("%d %s, ", len(h.GetItemMap(itemType)), itemType)

		for _, item := range h.GetItemMap(itemType) {
			if item.State.IsLocal() {
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
			h.logger.Warningf("failed to read hub index: %s", err)
		}
	} else if bytes.Equal(body, oldContent) {
		h.logger.Info("hub index is up to date")
		return nil
	}

	if err = os.WriteFile(h.local.HubIndexFile, body, 0o644); err != nil {
		return fmt.Errorf("failed to write hub index: %w", err)
	}

	h.logger.Infof("Wrote index to %s, %d bytes", h.local.HubIndexFile, len(body))

	return nil
}

func (h *Hub) addItem(item *Item) {
	if h.items[item.Type] == nil {
		h.items[item.Type] = make(map[string]*Item)
	}

	h.items[item.Type][item.Name] = item
}

// GetItemMap returns the map of items for a given type.
func (h *Hub) GetItemMap(itemType string) map[string]*Item {
	return h.items[itemType]
}

// GetItem returns an item from hub based on its type and full name (author/name).
func (h *Hub) GetItem(itemType string, itemName string) *Item {
	return h.GetItemMap(itemType)[itemName]
}

// GetItemFQ returns an item from hub based on its type and name (type:author/name).
func (h *Hub) GetItemFQ(itemFQName string) (*Item, error) {
	// type and name are separated by a colon
	parts := strings.Split(itemFQName, ":")

	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid item name %s", itemFQName)
	}

	m := h.GetItemMap(parts[0])
	if m == nil {
		return nil, fmt.Errorf("invalid item type %s", parts[0])
	}

	i := m[parts[1]]
	if i == nil {
		return nil, fmt.Errorf("item %s not found", parts[1])
	}

	return i, nil
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
	if !slices.Contains(ItemTypes, itemType) {
		return nil, fmt.Errorf("invalid item type %s", itemType)
	}

	items := h.items[itemType]

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
	if !slices.Contains(ItemTypes, itemType) {
		return nil, fmt.Errorf("invalid item type %s", itemType)
	}

	items := h.items[itemType]

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
