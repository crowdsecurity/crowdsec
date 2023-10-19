package cwhub

import (
	"fmt"

	"github.com/enescakir/emoji"
	"golang.org/x/mod/semver"
)

const (
	// managed item types
	COLLECTIONS   = "collections"
	PARSERS       = "parsers"
	POSTOVERFLOWS = "postoverflows"
	SCENARIOS     = "scenarios"
)

// XXX: The order is important, as it is used to range over sub-items in collections
var ItemTypes = []string{PARSERS, POSTOVERFLOWS, SCENARIOS, COLLECTIONS}

type HubItems map[string]map[string]Item

// ItemVersion is used to detect the version of a given item
// by comparing the hash of each version to the local file.
// If the item does not match any known version, it is considered tainted.
type ItemVersion struct {
	Digest     string `json:"digest,omitempty"`     // meow
	Deprecated bool   `json:"deprecated,omitempty"` // XXX: do we keep this?
}

// Item represents an object managed in the hub. It can be a parser, scenario, collection..
type Item struct {
	// descriptive info
	Type                 string   `json:"type,omitempty"                   yaml:"type,omitempty"`                   // parser|postoverflows|scenario|collection(|enrich)
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
	Installed    bool   `json:"installed,omitempty"`
	Downloaded   bool   `json:"downloaded,omitempty"`
	UpToDate     bool   `json:"up_to_date,omitempty"`
	Tainted      bool   `json:"tainted,omitempty"` // has it been locally modified
	Local        bool   `json:"local,omitempty"`   // if it's a non versioned control one

	// if it's a collection, it can have sub items
	Parsers       []string `json:"parsers,omitempty"       yaml:"parsers,omitempty"`
	PostOverflows []string `json:"postoverflows,omitempty" yaml:"postoverflows,omitempty"`
	Scenarios     []string `json:"scenarios,omitempty"     yaml:"scenarios,omitempty"`
	Collections   []string `json:"collections,omitempty"   yaml:"collections,omitempty"`
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
	if i.Local {
		managed = false
		status += ",local"
	}

	warning := false
	if i.Tainted {
		warning = true
		status += ",tainted"
	} else if !i.UpToDate && !i.Local {
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
	return semver.Compare("v"+i.Version, "v"+i.LocalVersion)
}

// validPath returns true if the (relative) path is allowed for the item
// dirNmae: the directory name (ie. crowdsecurity)
// fileName: the filename (ie. apache2-logs.yaml)
func (i *Item) validPath(dirName, fileName string) bool {
	return (dirName+"/"+fileName == i.Name+".yaml") || (dirName+"/"+fileName == i.Name+".yml")
}

// GetItemMap returns the map of items for a given type
func (h *Hub) GetItemMap(itemType string) map[string]Item {
	m, ok := h.Items[itemType]
	if !ok {
		return nil
	}

	return m
}

// GetItem returns the item from hub based on its type and full name (author/name)
func (h *Hub) GetItem(itemType string, itemName string) *Item {
	m, ok := h.GetItemMap(itemType)[itemName]
	if !ok {
		return nil
	}

	return &m
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

// AddItem adds an item to the hub index
func (h *Hub) AddItem(itemType string, item Item) error {
	for _, itype := range ItemTypes {
		if itype == itemType {
			h.Items[itemType][item.Name] = item
			return nil
		}
	}

	return fmt.Errorf("ItemType %s is unknown", itemType)
}

// GetInstalledItems returns the list of installed items
func (h *Hub) GetInstalledItems(itemType string) ([]Item, error) {
	items, ok := h.Items[itemType]
	if !ok {
		return nil, fmt.Errorf("no %s in hubIdx", itemType)
	}

	retItems := make([]Item, 0)

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

	for i, it := range items {
		retStr[i] = it.Name
	}

	return retStr, nil
}