package cwhub

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/Masterminds/semver/v3"
	yaml "gopkg.in/yaml.v3"
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

// The order is important, as it is used to range over sub-items in collections.
var ItemTypes = []string{PARSERS, POSTOVERFLOWS, SCENARIOS, CONTEXTS, APPSEC_CONFIGS, APPSEC_RULES, COLLECTIONS}

type HubItems map[string]map[string]*Item

// ItemVersion is used to detect the version of a given item
// by comparing the hash of each version to the local file.
// If the item does not match any known version, it is considered tainted (modified).
type ItemVersion struct {
	Digest     string `json:"digest,omitempty" yaml:"digest,omitempty"`
	Deprecated bool   `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
}

type Dependencies struct {
	Parsers       []string `json:"parsers,omitempty"        yaml:"parsers,omitempty"`
	PostOverflows []string `json:"postoverflows,omitempty"  yaml:"postoverflows,omitempty"`
	Scenarios     []string `json:"scenarios,omitempty"      yaml:"scenarios,omitempty"`
	Collections   []string `json:"collections,omitempty"    yaml:"collections,omitempty"`
	Contexts      []string `json:"contexts,omitempty"       yaml:"contexts,omitempty"`
	AppsecConfigs []string `json:"appsec-configs,omitempty" yaml:"appsec-configs,omitempty"`
	AppsecRules   []string `json:"appsec-rules,omitempty"   yaml:"appsec-rules,omitempty"`
}

// a group of items of the same type
type itemgroup struct {
	typeName  string
	itemNames []string
}

func (d Dependencies) byType() []itemgroup {
	return []itemgroup{
		{PARSERS, d.Parsers},
		{POSTOVERFLOWS, d.PostOverflows},
		{SCENARIOS, d.Scenarios},
		{CONTEXTS, d.Contexts},
		{APPSEC_CONFIGS, d.AppsecConfigs},
		{APPSEC_RULES, d.AppsecRules},
		{COLLECTIONS, d.Collections},
	}
}

// SubItems iterates over the sub-items in the struct, excluding the ones that were not found in the hub.
func (d Dependencies) SubItems(hub *Hub) func(func(*Item) bool) {
	return func(yield func(*Item) bool) {
		for _, typeGroup := range d.byType() {
			for _, name := range typeGroup.itemNames {
				s := hub.GetItem(typeGroup.typeName, name)
				if s == nil {
					continue
				}

				if !yield(s) {
					return
				}
			}
		}
	}
}

// Item is created from an index file and enriched with local info.
type Item struct {
	hub *Hub // back pointer to the hub, to retrieve other items and call install/remove methods

	State ItemState `json:"-" yaml:"-"` // local state, not stored in the index

	Type        string   `json:"type,omitempty"        yaml:"type,omitempty"`
	Stage       string   `json:"stage,omitempty"       yaml:"stage,omitempty"`     // Stage for parser|postoverflow: s00-raw/s01-...
	Name        string   `json:"name,omitempty"        yaml:"name,omitempty"`      // usually "author/name"
	FileName    string   `json:"file_name,omitempty"   yaml:"file_name,omitempty"` // eg. apache2-logs.yaml
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Content     string   `json:"content,omitempty"     yaml:"-"`
	References  []string `json:"references,omitempty"  yaml:"references,omitempty"`

	// NOTE: RemotePath could be derived from the other fields
	RemotePath string                 `json:"path,omitempty" yaml:"path,omitempty"`       // path relative to the base URL eg. /parsers/stage/author/file.yaml
	Version    string                 `json:"version,omitempty" yaml:"version,omitempty"` // the last available version
	Versions   map[string]ItemVersion `json:"versions,omitempty"  yaml:"-"`               // all the known versions

	// The index contains the dependencies of the "latest" version (collections only)
	Dependencies
}

// InstallPath returns the path to use for the install symlink.
// Returns an error if an item is already installed or if the path goes outside of the install dir.
func (i *Item) InstallPath() (string, error) {
	if i.State.Installed {
		return "", fmt.Errorf("%s is already installed at %s", i.FQName(), i.State.LocalPath)
	}

	p := i.Type
	if i.Stage != "" {
		p = filepath.Join(p, i.Stage)
	}

	return SafePath(i.hub.local.InstallDir, filepath.Join(p, i.FileName))
}

// DownloadPath returns the location of the actual config file in the hub
// (eg. /etc/crowdsec/hub/collections/author/xyz.yaml).
// Raises an error if the path goes outside of the hub dir.
func (i *Item) DownloadPath() (string, error) {
	ret, err := SafePath(i.hub.local.HubDir, i.RemotePath)
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

// LatestDependencies returns a slice of sub-items of the "latest" available version of the item, as opposed to the version that is actually installed. The information comes from the index.
func (i *Item) LatestDependencies() Dependencies {
	return i.Dependencies
}

// CurrentSubItems returns a slice of sub-items of the installed version, excluding the ones that were not found.
// The list comes from the content file if parseable, otherwise from the index (same as LatestDependencies).
func (i *Item) CurrentDependencies() Dependencies {
	if !i.HasSubItems() {
		return Dependencies{}
	}

	if i.State.UpToDate {
		return i.Dependencies
	}

	currentContent, err := os.ReadFile(i.State.LocalPath)
	if errors.Is(err, fs.ErrNotExist) {
		return i.Dependencies
	}

	if err != nil {
		// a file might be corrupted, or in development
		i.hub.logger.Warningf("can't read dependencies for %s, using index", i.FQName())
		return i.Dependencies
	}

	var d Dependencies

	// XXX: assume collection content never has multiple documents
	if err := yaml.Unmarshal(currentContent, &d); err != nil {
		i.hub.logger.Warningf("can't parse dependencies for %s, using index", i.FQName())
		return i.Dependencies
	}

	return d
}

func (i *Item) logMissingSubItems() {
	for _, sub := range i.CurrentDependencies().byType() {
		for _, subName := range sub.itemNames {
			if i.hub.GetItem(sub.typeName, subName) == nil {
				i.hub.logger.Errorf("can't find %s:%s, required by %s", sub.typeName, subName, i.Name)
			}
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

// SafeToRemoveDeps returns a slice of dependencies that can be safely removed when this item is removed.
// The returned slice can contain items that are not installed, or not downloaded.
func (i *Item) SafeToRemoveDeps() ([]*Item, error) {
	ret := make([]*Item, 0)

	// can return err for circular dependencies
	descendants, err := i.descendants()
	if err != nil {
		return nil, err
	}

	ancestors := i.Ancestors()

	for sub := range i.CurrentDependencies().SubItems(i.hub) {
		safe := true

		// if the sub depends on a collection that is not a direct or indirect dependency
		// of the current item, it is not removed
		for _, subParent := range sub.Ancestors() {
			if !subParent.State.Installed {
				continue
			}

			// the ancestor that would block the removal of the sub item is also an ancestor
			// of the item we are removing, so we don't want false warnings
			// (e.g. crowdsecurity/sshd-logs was not removed because it also belongs to crowdsecurity/linux,
			// while we are removing crowdsecurity/sshd)
			if slices.Contains(ancestors, subParent) {
				continue
			}

			// the sub-item belongs to the item we are removing, but we already knew that
			if subParent == i {
				continue
			}

			if !slices.Contains(descendants, subParent) {
				// not removing %s because it also belongs to %s", sub.FQName(), subParent.FQName())
				safe = false
				break
			}
		}

		if safe {
			ret = append(ret, sub)
		}
	}

	return ret, nil
}

// descendants returns a list of all (direct or indirect) dependencies of the item's current version.
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

		for subItem := range item.CurrentDependencies().SubItems(item.hub) {
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

// latestHash() returns the hash of the latest version of the item.
// if it's missing, the index file has been manually modified or got corrupted.
func (i *Item) latestHash() string {
	for k, v := range i.Versions {
		if k == i.Version {
			return v.Digest
		}
	}

	return ""
}
