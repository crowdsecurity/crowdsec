package cwhub

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/enescakir/emoji"
	log "github.com/sirupsen/logrus"
)

const (
	// managed item types.
	COLLECTIONS   = "collections"
	PARSERS       = "parsers"
	POSTOVERFLOWS = "postoverflows"
	SCENARIOS     = "scenarios"
	WAAP_CONFIGS  = "waap-configs"
	WAAP_RULES    = "waap-rules"
)

const (
	versionUpToDate        = iota // the latest version from index is installed
	versionUpdateAvailable        // not installed, or lower than latest
	versionUnknown                // local file with no version, or invalid version number
	versionFuture                 // local version is higher latest, but is included in the index: should not happen
)

var (
	// The order is important, as it is used to range over sub-items in collections.
	ItemTypes = []string{PARSERS, POSTOVERFLOWS, SCENARIOS, WAAP_CONFIGS, WAAP_RULES, COLLECTIONS}
)

type HubItems map[string]map[string]*Item

// ItemVersion is used to detect the version of a given item
// by comparing the hash of each version to the local file.
// If the item does not match any known version, it is considered tainted (modified).
type ItemVersion struct {
	Digest     string `json:"digest,omitempty" yaml:"digest,omitempty"`
	Deprecated bool   `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
}

// ItemState is used to keep the local state (i.e. at runtime) of an item.
// This data is not stored in the index, but is displayed with "cscli ... inspect".
type ItemState struct {
	LocalPath            string   `json:"local_path,omitempty" yaml:"local_path,omitempty"`
	LocalVersion         string   `json:"local_version,omitempty" yaml:"local_version,omitempty"`
	LocalHash            string   `json:"local_hash,omitempty" yaml:"local_hash,omitempty"`
	Installed            bool     `json:"installed"`
	Downloaded           bool     `json:"downloaded"`
	UpToDate             bool     `json:"up_to_date"`
	Tainted              bool     `json:"tainted"`
	BelongsToCollections []string `json:"belongs_to_collections,omitempty" yaml:"belongs_to_collections,omitempty"`
}

// Item is created from an index file and enriched with local info.
type Item struct {
	hub *Hub // back pointer to the hub, to retrieve other items and call install/remove methods

	State ItemState `json:"-" yaml:"-"` // local state, not stored in the index

	Type        string   `json:"type,omitempty" yaml:"type,omitempty"`           // one of the ItemTypes
	Stage       string   `json:"stage,omitempty" yaml:"stage,omitempty"`         // Stage for parser|postoverflow: s00-raw/s01-...
	Name        string   `json:"name,omitempty" yaml:"name,omitempty"`           // usually "author/name"
	FileName    string   `json:"file_name,omitempty" yaml:"file_name,omitempty"` // eg. apache2-logs.yaml
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Author      string   `json:"author,omitempty" yaml:"author,omitempty"`
	References  []string `json:"references,omitempty" yaml:"references,omitempty"`

	RemotePath string                 `json:"path,omitempty" yaml:"remote_path,omitempty"` // path relative to the base URL eg. /parsers/stage/author/file.yaml
	Version    string                 `json:"version,omitempty" yaml:"version,omitempty"`  // the last available version
	Versions   map[string]ItemVersion `json:"versions,omitempty"  yaml:"-"`                // all the known versions

	// if it's a collection, it can have sub items
	Parsers       []string `json:"parsers,omitempty" yaml:"parsers,omitempty"`
	PostOverflows []string `json:"postoverflows,omitempty" yaml:"postoverflows,omitempty"`
	Scenarios     []string `json:"scenarios,omitempty" yaml:"scenarios,omitempty"`
	Collections   []string `json:"collections,omitempty" yaml:"collections,omitempty"`
	WaapConfigs   []string `json:"waap-configs,omitempty"   yaml:"waap-configs,omitempty"`
	WaapRules     []string `json:"waap-rules,omitempty"   yaml:"waap-rules,omitempty"`
}

// HasSubItems returns true if items of this type can have sub-items. Currently only collections.
func (i *Item) HasSubItems() bool {
	return i.Type == COLLECTIONS
}

// IsLocal returns true if the item has been create by a user (not downloaded from the hub).
func (i *Item) IsLocal() bool {
	return i.State.Installed && !i.State.Downloaded
}

// MarshalJSON is used to prepare the output for "cscli ... inspect -o json".
// It must not use a pointer receiver.
func (i Item) MarshalJSON() ([]byte, error) {
	type Alias Item

	return json.Marshal(&struct {
		Alias
		// we have to repeat the fields here, json will have inline support in v2
		LocalPath            string   `json:"local_path,omitempty"`
		LocalVersion         string   `json:"local_version,omitempty"`
		LocalHash            string   `json:"local_hash,omitempty"`
		Installed            bool     `json:"installed"`
		Downloaded           bool     `json:"downloaded"`
		UpToDate             bool     `json:"up_to_date"`
		Tainted              bool     `json:"tainted"`
		Local                bool     `json:"local"`
		BelongsToCollections []string `json:"belongs_to_collections,omitempty"`
	}{
		Alias:                Alias(i),
		LocalPath:            i.State.LocalPath,
		LocalVersion:         i.State.LocalVersion,
		LocalHash:            i.State.LocalHash,
		Installed:            i.State.Installed,
		Downloaded:           i.State.Downloaded,
		UpToDate:             i.State.UpToDate,
		Tainted:              i.State.Tainted,
		BelongsToCollections: i.State.BelongsToCollections,
		Local:                i.IsLocal(),
	})
}

// MarshalYAML is used to prepare the output for "cscli ... inspect -o raw".
// It must not use a pointer receiver.
func (i Item) MarshalYAML() (interface{}, error) {
	type Alias Item

	return &struct {
		Alias `yaml:",inline"`
		State ItemState `yaml:",inline"`
		Local bool      `yaml:"local"`
	}{
		Alias: Alias(i),
		State: i.State,
		Local: i.IsLocal(),
	}, nil
}

// SubItems returns a slice of sub-items, excluding the ones that were not found.
func (i *Item) SubItems() []*Item {
	sub := make([]*Item, 0)

	for _, name := range i.Parsers {
		s := i.hub.GetItem(PARSERS, name)
		if s == nil {
			continue
		}

		sub = append(sub, s)
	}

	for _, name := range i.PostOverflows {
		s := i.hub.GetItem(POSTOVERFLOWS, name)
		if s == nil {
			continue
		}

		sub = append(sub, s)
	}

	for _, name := range i.Scenarios {
		s := i.hub.GetItem(SCENARIOS, name)
		if s == nil {
			continue
		}

		sub = append(sub, s)
	}

	for _, name := range i.WaapConfigs {
		s := i.hub.GetItem(WAAP_CONFIGS, name)
		if s == nil {
			continue
		}

		sub = append(sub, s)
	}

	for _, name := range i.WaapRules {
		s := i.hub.GetItem(WAAP_RULES, name)
		if s == nil {
			continue
		}

		sub = append(sub, s)
	}

	for _, name := range i.Collections {
		s := i.hub.GetItem(COLLECTIONS, name)
		if s == nil {
			continue
		}

		sub = append(sub, s)
	}

	return sub
}

func (i *Item) logMissingSubItems() {
	if !i.HasSubItems() {
		return
	}

	for _, subName := range i.Parsers {
		if i.hub.GetItem(PARSERS, subName) == nil {
			log.Errorf("can't find %s in %s, required by %s", subName, PARSERS, i.Name)
		}
	}

	for _, subName := range i.Scenarios {
		if i.hub.GetItem(SCENARIOS, subName) == nil {
			log.Errorf("can't find %s in %s, required by %s", subName, SCENARIOS, i.Name)
		}
	}

	for _, subName := range i.PostOverflows {
		if i.hub.GetItem(POSTOVERFLOWS, subName) == nil {
			log.Errorf("can't find %s in %s, required by %s", subName, POSTOVERFLOWS, i.Name)
		}
	}

	for _, subName := range i.WaapConfigs {
		if i.hub.GetItem(WAAP_CONFIGS, subName) == nil {
			log.Errorf("can't find %s in %s, required by %s", subName, WAAP_CONFIGS, i.Name)
		}
	}

	for _, subName := range i.WaapRules {
		if i.hub.GetItem(WAAP_RULES, subName) == nil {
			log.Errorf("can't find %s in %s, required by %s", subName, WAAP_RULES, i.Name)
		}
	}

	for _, subName := range i.Collections {
		if i.hub.GetItem(COLLECTIONS, subName) == nil {
			log.Errorf("can't find %s in %s, required by %s", subName, COLLECTIONS, i.Name)
		}
	}
}

// Ancestors returns a slice of items (typically collections) that have this item as a direct or indirect dependency.
func (i *Item) Ancestors() []*Item {
	ret := make([]*Item, 0)

	for _, parentName := range i.State.BelongsToCollections {
		parent := i.hub.GetItem(COLLECTIONS, parentName)
		if parent == nil {
			continue
		}

		ret = append(ret, parent)
	}

	return ret
}

// InstallStatus returns the status of the item as a string and an emoji
// (eg. "enabled,update-available" and emoji.Warning).
func (i *Item) InstallStatus() (string, emoji.Emoji) {
	status := "disabled"
	ok := false

	if i.State.Installed {
		ok = true
		status = "enabled"
	}

	managed := true
	if i.IsLocal() {
		managed = false
		status += ",local"
	}

	warning := false
	if i.State.Tainted {
		warning = true
		status += ",tainted"
	} else if !i.State.UpToDate && !i.IsLocal() {
		warning = true
		status += ",update-available"
	}

	emo := emoji.QuestionMark

	switch {
	case !managed:
		emo = emoji.House
	case !i.State.Installed:
		emo = emoji.Prohibited
	case warning:
		emo = emoji.Warning
	case ok:
		emo = emoji.CheckMark
	}

	return status, emo
}

// versionStatus returns the status of the item version compared to the hub version.
// semver requires the 'v' prefix.
func (i *Item) versionStatus() int {
	local, err := semver.NewVersion(i.State.LocalVersion)
	if err != nil {
		return versionUnknown
	}

	// hub versions are already validated while syncing, ignore errors
	latest, _ := semver.NewVersion(i.Version)

	if local.LessThan(latest) {
		return versionUpdateAvailable
	}

	if local.Equal(latest) {
		return versionUpToDate
	}

	return versionFuture
}

// validPath returns true if the (relative) path is allowed for the item.
// dirNname: the directory name (ie. crowdsecurity).
// fileName: the filename (ie. apache2-logs.yaml).
func (i *Item) validPath(dirName, fileName string) bool {
	return (dirName+"/"+fileName == i.Name+".yaml") || (dirName+"/"+fileName == i.Name+".yml")
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

// SortItemSlice sorts a slice of items by name, case insensitive.
func SortItemSlice(items []*Item) {
	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
}
