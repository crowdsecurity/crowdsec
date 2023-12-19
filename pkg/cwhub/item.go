package cwhub

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/Masterminds/semver/v3"
	"github.com/enescakir/emoji"
	"slices"
)

const (
	// managed item types.
	COLLECTIONS    = "collections"
	PARSERS        = "parsers"
	POSTOVERFLOWS  = "postoverflows"
	SCENARIOS      = "scenarios"
	CONTEXTS       = "contexts"
	APPSEC_CONFIGS = "appsec-configs"
	APPSEC_RULES   = "appsec-rules"
)

const (
	versionUpToDate        = iota // the latest version from index is installed
	versionUpdateAvailable        // not installed, or lower than latest
	versionUnknown                // local file with no version, or invalid version number
	versionFuture                 // local version is higher latest, but is included in the index: should not happen
)

var (
	// The order is important, as it is used to range over sub-items in collections.
	ItemTypes = []string{PARSERS, POSTOVERFLOWS, SCENARIOS, CONTEXTS, APPSEC_CONFIGS, APPSEC_RULES, COLLECTIONS}
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
	TaintedBy            []string `json:"tainted_by,omitempty" yaml:"tainted_by,omitempty"`
	BelongsToCollections []string `json:"belongs_to_collections,omitempty" yaml:"belongs_to_collections,omitempty"`
}

// IsLocal returns true if the item has been create by a user (not downloaded from the hub).
func (s *ItemState) IsLocal() bool {
	return s.Installed && !s.Downloaded
}

// Text returns the status of the item as a string (eg. "enabled,update-available").
func (s *ItemState) Text() string {
	ret := "disabled"

	if s.Installed {
		ret = "enabled"
	}

	if s.IsLocal() {
		ret += ",local"
	}

	if s.Tainted {
		ret += ",tainted"
	} else if !s.UpToDate && !s.IsLocal() {
		ret += ",update-available"
	}

	return ret
}

// Emoji returns the status of the item as an emoji (eg. emoji.Warning).
func (s *ItemState) Emoji() emoji.Emoji {
	switch {
	case s.IsLocal():
		return emoji.House
	case !s.Installed:
		return emoji.Prohibited
	case s.Tainted || (!s.UpToDate && !s.IsLocal()):
		return emoji.Warning
	case s.Installed:
		return emoji.CheckMark
	default:
		return emoji.QuestionMark
	}
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

	RemotePath string                 `json:"path,omitempty" yaml:"path,omitempty"`       // path relative to the base URL eg. /parsers/stage/author/file.yaml
	Version    string                 `json:"version,omitempty" yaml:"version,omitempty"` // the last available version
	Versions   map[string]ItemVersion `json:"versions,omitempty"  yaml:"-"`               // all the known versions

	// if it's a collection, it can have sub items
	Parsers       []string `json:"parsers,omitempty" yaml:"parsers,omitempty"`
	PostOverflows []string `json:"postoverflows,omitempty" yaml:"postoverflows,omitempty"`
	Scenarios     []string `json:"scenarios,omitempty" yaml:"scenarios,omitempty"`
	Collections   []string `json:"collections,omitempty" yaml:"collections,omitempty"`
	Contexts      []string `json:"contexts,omitempty" yaml:"contexts,omitempty"`
	AppsecConfigs []string `json:"appsec-configs,omitempty"   yaml:"appsec-configs,omitempty"`
	AppsecRules   []string `json:"appsec-rules,omitempty"   yaml:"appsec-rules,omitempty"`
}

// installPath returns the location of the symlink to the item in the hub, or the path of the item itself if it's local
// (eg. /etc/crowdsec/collections/xyz.yaml).
// Raises an error if the path goes outside of the install dir.
func (i *Item) installPath() (string, error) {
	p := i.Type
	if i.Stage != "" {
		p = filepath.Join(p, i.Stage)
	}

	return safePath(i.hub.local.InstallDir, filepath.Join(p, i.FileName))
}

// downloadPath returns the location of the actual config file in the hub
// (eg. /etc/crowdsec/hub/collections/author/xyz.yaml).
// Raises an error if the path goes outside of the hub dir.
func (i *Item) downloadPath() (string, error) {
	ret, err := safePath(i.hub.local.HubDir, i.RemotePath)
	if err != nil {
		return "", err
	}

	return ret, nil
}

// HasSubItems returns true if items of this type can have sub-items. Currently only collections.
func (i *Item) HasSubItems() bool {
	return i.Type == COLLECTIONS
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
		Local:                i.State.IsLocal(),
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
		Local: i.State.IsLocal(),
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

	for _, name := range i.Contexts {
		s := i.hub.GetItem(CONTEXTS, name)
		if s == nil {
			continue
		}

		sub = append(sub, s)
	}

	for _, name := range i.AppsecConfigs {
		s := i.hub.GetItem(APPSEC_CONFIGS, name)
		if s == nil {
			continue
		}

		sub = append(sub, s)
	}

	for _, name := range i.AppsecRules {
		s := i.hub.GetItem(APPSEC_RULES, name)
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
			i.hub.logger.Errorf("can't find %s in %s, required by %s", subName, PARSERS, i.Name)
		}
	}

	for _, subName := range i.Scenarios {
		if i.hub.GetItem(SCENARIOS, subName) == nil {
			i.hub.logger.Errorf("can't find %s in %s, required by %s", subName, SCENARIOS, i.Name)
		}
	}

	for _, subName := range i.PostOverflows {
		if i.hub.GetItem(POSTOVERFLOWS, subName) == nil {
			i.hub.logger.Errorf("can't find %s in %s, required by %s", subName, POSTOVERFLOWS, i.Name)
		}
	}

	for _, subName := range i.Contexts {
		if i.hub.GetItem(CONTEXTS, subName) == nil {
			i.hub.logger.Errorf("can't find %s in %s, required by %s", subName, CONTEXTS, i.Name)
		}
	}

	for _, subName := range i.AppsecConfigs {
		if i.hub.GetItem(APPSEC_CONFIGS, subName) == nil {
			i.hub.logger.Errorf("can't find %s in %s, required by %s", subName, APPSEC_CONFIGS, i.Name)
		}
	}

	for _, subName := range i.AppsecRules {
		if i.hub.GetItem(APPSEC_RULES, subName) == nil {
			i.hub.logger.Errorf("can't find %s in %s, required by %s", subName, APPSEC_RULES, i.Name)
		}
	}

	for _, subName := range i.Collections {
		if i.hub.GetItem(COLLECTIONS, subName) == nil {
			i.hub.logger.Errorf("can't find %s in %s, required by %s", subName, COLLECTIONS, i.Name)
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

// descendants returns a list of all (direct or indirect) dependencies of the item.
func (i *Item) descendants() ([]*Item, error) {
	var collectSubItems func(item *Item, visited map[*Item]bool, result *[]*Item) error

	collectSubItems = func(item *Item, visited map[*Item]bool, result *[]*Item) error {
		if item == nil {
			return nil
		}

		if visited[item] {
			return nil
		}

		visited[item] = true

		for _, subItem := range item.SubItems() {
			if subItem == i {
				return fmt.Errorf("circular dependency detected: %s depends on %s", item.Name, i.Name)
			}

			*result = append(*result, subItem)

			err := collectSubItems(subItem, visited, result)
			if err != nil {
				return err
			}
		}

		return nil
	}

	ret := []*Item{}
	visited := map[*Item]bool{}

	err := collectSubItems(i, visited, &ret)
	if err != nil {
		return nil, err
	}

	return ret, nil
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

// FQName returns the fully qualified name of the item (ie. parsers:crowdsecurity/apache2-logs).
func (i *Item) FQName() string {
	return fmt.Sprintf("%s:%s", i.Type, i.Name)
}

// addTaint marks the item as tainted, and propagates the taint to the ancestors.
// sub: the sub-item that caused the taint. May be the item itself!
func (i *Item) addTaint(sub *Item) {
	i.State.Tainted = true
	taintedBy := sub.FQName()

	idx, ok := slices.BinarySearch(i.State.TaintedBy, taintedBy)
	if ok {
		return
	}

	// insert the taintedBy in the slice

	i.State.TaintedBy = append(i.State.TaintedBy, "")

	copy(i.State.TaintedBy[idx+1:], i.State.TaintedBy[idx:])

	i.State.TaintedBy[idx] = taintedBy

	i.hub.logger.Debugf("%s is tainted by %s", i.Name, taintedBy)

	// propagate the taint to the ancestors

	for _, ancestor := range i.Ancestors() {
		ancestor.addTaint(sub)
	}
}
