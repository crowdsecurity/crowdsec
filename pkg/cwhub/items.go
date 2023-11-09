package cwhub

import (
	"encoding/json"
	"fmt"

	"github.com/Masterminds/semver/v3"
	"github.com/enescakir/emoji"
)

const (
	// managed item types
	COLLECTIONS   = "collections"
	PARSERS       = "parsers"
	POSTOVERFLOWS = "postoverflows"
	SCENARIOS     = "scenarios"
)

const (
	VersionUpToDate = iota
	VersionUpdateAvailable
	VersionUnknown
	VersionFuture
)

// The order is important, as it is used to range over sub-items in collections
var ItemTypes = []string{PARSERS, POSTOVERFLOWS, SCENARIOS, COLLECTIONS}

type HubItems map[string]map[string]*Item

// ItemVersion is used to detect the version of a given item
// by comparing the hash of each version to the local file.
// If the item does not match any known version, it is considered tainted.
type ItemVersion struct {
	Digest     string `json:"digest,omitempty"`     // meow
	Deprecated bool   `json:"deprecated,omitempty"` // XXX: do we keep this?
}

// Item represents an object managed in the hub. It can be a parser, scenario, collection..
type Item struct {
	// back pointer to the hub, to retrieve subitems and call install/remove methods
	hub *Hub

	// descriptive info
	Type                 string   `json:"type,omitempty"                   yaml:"type,omitempty"`                   // can be any of the ItemTypes
	Stage                string   `json:"stage,omitempty"                  yaml:"stage,omitempty"`                  // Stage for parser|postoverflow: s00-raw/s01-...
	Name                 string   `json:"name,omitempty"`                                                           // as seen in .index.json, usually "author/name"
	FileName             string   `json:"file_name,omitempty"`                                                      // the filename, ie. apache2-logs.yaml
	Description          string   `json:"description,omitempty"            yaml:"description,omitempty"`            // as seen in .index.json
	Author               string   `json:"author,omitempty"`                                                         // as seen in .index.json
	References           []string `json:"references,omitempty"             yaml:"references,omitempty"`             // as seen in .index.json
	BelongsToCollections []string `json:"belongs_to_collections,omitempty" yaml:"belongs_to_collections,omitempty"` // parent collection if any

	// remote (hub) info
	RemotePath string                 `json:"path,omitempty"      yaml:"remote_path,omitempty"` // the path relative to (git | hub API) ie. /parsers/stage/author/file.yaml
	Version    string                 `json:"version,omitempty"`                                // the last version
	Versions   map[string]ItemVersion `json:"versions,omitempty"  yaml:"-"`                     // the list of existing versions

	// local (deployed) info
	LocalPath    string `json:"local_path,omitempty" yaml:"local_path,omitempty"` // the local path relative to ${CFG_DIR}
	LocalVersion string `json:"local_version,omitempty"`
	LocalHash    string `json:"local_hash,omitempty"` // the local meow
	Installed    bool   `json:"installed,omitempty"`  // XXX: should we remove omitempty from bool fields?
	Downloaded   bool   `json:"downloaded,omitempty"`
	UpToDate     bool   `json:"up_to_date,omitempty"`
	Tainted      bool   `json:"tainted,omitempty"` // has it been locally modified?

	// if it's a collection, it can have sub items
	Parsers       []string `json:"parsers,omitempty"       yaml:"parsers,omitempty"`
	PostOverflows []string `json:"postoverflows,omitempty" yaml:"postoverflows,omitempty"`
	Scenarios     []string `json:"scenarios,omitempty"     yaml:"scenarios,omitempty"`
	Collections   []string `json:"collections,omitempty"   yaml:"collections,omitempty"`
}

type SubItem struct {
	Type string
	Name string
}

func (i *Item) HasSubItems() bool {
	return i.Type == COLLECTIONS
}

func (i *SubItem) HasSubItems() bool {
	return i.Type == COLLECTIONS
}

func (i *Item) IsLocal() bool {
	return i.Installed && !i.Downloaded
}

// MarshalJSON is used to add the "local" field to the json output
// (i.e. with cscli ... inspect -o json)
// It must not use a pointer receiver
func (i Item) MarshalJSON() ([]byte, error) {
	type Alias Item

	return json.Marshal(&struct {
		Alias
		Local bool `json:"local"` // XXX: omitempty?
	}{
		Alias: Alias(i),
		Local: i.IsLocal(),
	})
}

// MarshalYAML is used to add the "local" field to the yaml output
// (i.e. with cscli ... inspect -o raw)
// It must not use a pointer receiver
func (i Item) MarshalYAML() (interface{}, error) {
	type Alias Item

	return &struct {
		Alias `yaml:",inline"`
		Local bool `yaml:"local"`
	}{
		Alias: Alias(i),
		Local: i.IsLocal(),
	}, nil
}

// SubItems returns the list of sub items for a given item (typically a collection)
func (i *Item) SubItems() []SubItem {
	sub := make([]SubItem,
		len(i.Parsers)+
			len(i.PostOverflows)+
			len(i.Scenarios)+
			len(i.Collections))

	n := 0

	for _, name := range i.Parsers {
		sub[n] = SubItem{Type: PARSERS, Name: name}
		n++
	}

	for _, name := range i.PostOverflows {
		sub[n] = SubItem{Type: POSTOVERFLOWS, Name: name}
		n++
	}

	for _, name := range i.Scenarios {
		sub[n] = SubItem{Type: SCENARIOS, Name: name}
		n++
	}

	for _, name := range i.Collections {
		sub[n] = SubItem{Type: COLLECTIONS, Name: name}
		n++
	}

	return sub
}

// Status returns the status of the item as a string and an emoji
// ie. "enabled,update-available" and emoji.Warning
func (i *Item) Status() (string, emoji.Emoji) {
	status := "disabled"
	ok := false

	if i.Installed {
		ok = true
		status = "enabled"
	}

	managed := true
	if i.IsLocal() {
		managed = false
		status += ",local"
	}

	warning := false
	if i.Tainted {
		warning = true
		status += ",tainted"
	} else if !i.UpToDate && !i.IsLocal() {
		warning = true
		status += ",update-available"
	}

	emo := emoji.QuestionMark

	switch {
	case !managed:
		emo = emoji.House
	case !i.Installed:
		emo = emoji.Prohibited
	case warning:
		emo = emoji.Warning
	case ok:
		emo = emoji.CheckMark
	}

	return status, emo
}

// versionStatus: semver requires 'v' prefix
func (i *Item) versionStatus() int {
	local, err := semver.NewVersion(i.LocalVersion)
	if err != nil {
		return VersionUnknown
	}

	// hub versions are already validated while syncing, ignore errors
	latest, _ := semver.NewVersion(i.Version)

	if local.LessThan(latest) {
		return VersionUpdateAvailable
	}

	if local.Equal(latest) {
		return VersionUpToDate
	}

	return VersionFuture
}

// validPath returns true if the (relative) path is allowed for the item
// dirNmae: the directory name (ie. crowdsecurity)
// fileName: the filename (ie. apache2-logs.yaml)
func (i *Item) validPath(dirName, fileName string) bool {
	return (dirName+"/"+fileName == i.Name+".yaml") || (dirName+"/"+fileName == i.Name+".yml")
}

// GetItemMap returns the map of items for a given type
func (h *Hub) GetItemMap(itemType string) map[string]*Item {
	return h.Items[itemType]
}

// GetItem returns the item from hub based on its type and full name (author/name)
func (h *Hub) GetItem(itemType string, itemName string) *Item {
	return h.GetItemMap(itemType)[itemName]
}

// GetItemNames returns the list of item (full) names for a given type
// ie. for parsers: crowdsecurity/apache2 crowdsecurity/nginx
// The names can be used to retrieve the item with GetItem()
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

// GetInstalledItems returns the list of installed items
func (h *Hub) GetInstalledItems(itemType string) ([]*Item, error) {
	items, ok := h.Items[itemType]
	if !ok {
		return nil, fmt.Errorf("no %s in the hub index", itemType)
	}

	retItems := make([]*Item, 0)

	for _, item := range items {
		if item.Installed {
			retItems = append(retItems, item)
		}
	}

	return retItems, nil
}

// GetInstalledItemsAsString returns the names of the installed items
func (h *Hub) GetInstalledItemsAsString(itemType string) ([]string, error) {
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
