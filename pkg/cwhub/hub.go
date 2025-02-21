package cwhub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/maptools"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

// Hub is the main structure for the package.
type Hub struct {
	items     HubItems // Items read from HubDir and InstallDir
	pathIndex map[string]*Item
	local     *csconfig.LocalHubCfg
	logger    *logrus.Logger
	Warnings  []string // Warnings encountered during sync
}

// GetDataDir returns the data directory, where data sets are installed.
func (h *Hub) GetDataDir() string {
	return h.local.InstallDataDir
}

// NewHub returns a new Hub instance with local and (optionally) remote configuration.
// The hub is not synced automatically. Load() must be called to read the index, sync the local state,
// and check for unmanaged items.
func NewHub(local *csconfig.LocalHubCfg, logger *logrus.Logger) (*Hub, error) {
	if local == nil {
		return nil, errors.New("no hub configuration provided")
	}

	if logger == nil {
		logger = logrus.New()
		logger.SetOutput(io.Discard)
	}

	hub := &Hub{
		local:     local,
		logger:    logger,
		pathIndex: make(map[string]*Item, 0),
	}

	return hub, nil
}

// Load reads the state of the items on disk.
func (h *Hub) Load() error {
	h.logger.Debugf("loading hub idx %s", h.local.HubIndexFile)

	if err := h.parseIndex(); err != nil {
		return fmt.Errorf("invalid hub index: %w. Run 'sudo cscli hub update' to download the index again", err)
	}

	return h.localSync()
}

// parseIndex takes the content of an index file and fills the map of associated parsers/scenarios/collections.
func (h *Hub) parseIndex() error {
	bidx, err := os.ReadFile(h.local.HubIndexFile)
	if err != nil {
		return fmt.Errorf("unable to read index file: %w", err)
	}

	if err := json.Unmarshal(bidx, &h.items); err != nil {
		return fmt.Errorf("failed to parse index: %w", err)
	}

	// Iterate over the different types to complete the struct
	for _, itemType := range ItemTypes {
		for name, item := range h.GetItemMap(itemType) {
			if item == nil {
				// likely defined as empty object or null in the index file
				return fmt.Errorf("%s:%s has no index metadata", itemType, name)
			}

			if item.RemotePath == "" {
				return fmt.Errorf("%s:%s has no download path", itemType, name)
			}

			if (itemType == PARSERS || itemType == POSTOVERFLOWS) && item.Stage == "" {
				return fmt.Errorf("%s:%s has no stage", itemType, name)
			}

			item.hub = h
			item.Name = name

			item.Type = itemType
			item.FileName = path.Base(item.RemotePath)

			item.logMissingSubItems()

			if item.latestHash() == "" {
				h.logger.Errorf("invalid hub item %s: latest version missing from index", item.FQName())
			}
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
		items := h.GetItemsByType(itemType, false)
		if len(items) == 0 {
			continue
		}

		loaded += fmt.Sprintf("%d %s, ", len(items), itemType)

		for _, item := range items {
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
		"Loaded: " + loaded,
	}

	if local > 0 || tainted > 0 {
		ret = append(ret, fmt.Sprintf("Unmanaged items: %d local, %d tainted", local, tainted))
	}

	return ret
}

var ErrUpdateAfterSync = errors.New("cannot update hub index after load/sync")

// Update downloads the latest version of the index and writes it to disk if it changed.
// It cannot be called after Load() unless the index was completely empty.
func (h *Hub) Update(ctx context.Context, indexProvider IndexProvider, withContent bool) (bool, error) {
	if len(h.items) > 0 {
		// if this happens, it's a bug.
		return false, ErrUpdateAfterSync
	}

	return indexProvider.FetchIndex(ctx, h.local.HubIndexFile, withContent, h.logger)
}

// addItem adds an item to the hub. It silently replaces an existing item with the same type and name.
func (h *Hub) addItem(item *Item) {
	if h.items[item.Type] == nil {
		h.items[item.Type] = make(map[string]*Item)
	}

	h.items[item.Type][item.Name] = item
	h.pathIndex[item.State.LocalPath] = item
}

// GetItemMap returns the map of items for a given type.
func (h *Hub) GetItemMap(itemType string) map[string]*Item {
	return h.items[itemType]
}

// GetItem returns an item from hub based on its type and full name (author/name).
func (h *Hub) GetItem(itemType string, itemName string) *Item {
	return h.GetItemMap(itemType)[itemName]
}

// GetItemByPath returns an item from hub based on its (absolute) local path.
func (h *Hub) GetItemByPath(itemPath string) *Item {
	return h.pathIndex[itemPath]
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

// GetItemsByType returns a slice of all the items of a given type, installed or not, optionally sorted by case-insensitive name.
// A non-existent type will silently return an empty slice.
func (h *Hub) GetItemsByType(itemType string, sorted bool) []*Item {
	items := h.items[itemType]

	ret := make([]*Item, len(items))

	if sorted {
		for idx, name := range maptools.SortedKeysNoCase(items) {
			ret[idx] = items[name]
		}

		return ret
	}

	idx := 0

	for _, item := range items {
		ret[idx] = item
		idx += 1
	}

	return ret
}

// GetInstalledByType returns a slice of all the installed items of a given type, optionally sorted by case-insensitive name.
// A non-existent type will silently return an empty slice.
func (h *Hub) GetInstalledByType(itemType string, sorted bool) []*Item {
	ret := make([]*Item, 0)

	for _, item := range h.GetItemsByType(itemType, sorted) {
		if item.State.Installed {
			ret = append(ret, item)
		}
	}

	return ret
}

// GetInstalledListForAPI returns a slice of names of all the installed scenarios and appsec-rules.
// The returned list is sorted by type (scenarios first) and case-insensitive name.
func (h *Hub) GetInstalledListForAPI() []string {
	scenarios := h.GetInstalledByType(SCENARIOS, true)
	appsecRules := h.GetInstalledByType(APPSEC_RULES, true)

	ret := make([]string, len(scenarios)+len(appsecRules))

	idx := 0

	for _, item := range scenarios {
		ret[idx] = item.Name
		idx += 1
	}

	for _, item := range appsecRules {
		ret[idx] = item.Name
		idx += 1
	}

	return ret
}
