// Package cwhub is responsible for installing and upgrading the local hub files.
//
// This includes retrieving the index, the items to install (parsers, scenarios, data files...)
// and managing the dependencies and taints.
package cwhub

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/enescakir/emoji"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"
)

const (
	HubIndexFile = ".index.json"

	// managed item types
	PARSERS       = "parsers"
	PARSERS_OVFLW = "postoverflows"
	SCENARIOS     = "scenarios"
	COLLECTIONS   = "collections"
)

var (
	ItemTypes = []string{PARSERS, PARSERS_OVFLW, SCENARIOS, COLLECTIONS}

	ErrMissingReference = errors.New("Reference(s) missing in collection")

	// XXX: can we remove these globals?
	skippedLocal       = 0
	skippedTainted     = 0
	RawFileURLTemplate = "https://hub-cdn.crowdsec.net/%s/%s"
	HubBranch          = "master"
	hubIdx             map[string]map[string]Item
)

// ItemVersion is used to detect the version of a given item
// by comparing the hash of each version to the local file.
// If the item does not match any known version, it is considered tainted.
type ItemVersion struct {
	Digest     string `json:"digest,omitempty"`     // meow
	Deprecated bool   `json:"deprecated,omitempty"` // XXX: do we keep this?
}

// Item can be: parser, scenario, collection..
type Item struct {
	// descriptive info
	Type                 string   `json:"type,omitempty"                   yaml:"type,omitempty"`                   // parser|postoverflows|scenario|collection(|enrich)
	Stage                string   `json:"stage,omitempty"                  yaml:"stage,omitempty"`                  // Stage for parser|postoverflow: s00-raw/s01-...
	Name                 string   `json:"name,omitempty"`                                                           // as seen in .config.json, usually "author/name"
	FileName             string   `json:"file_name,omitempty"`                                                      // the filename, ie. apache2-logs.yaml
	Description          string   `json:"description,omitempty"            yaml:"description,omitempty"`            // as seen in .config.json
	Author               string   `json:"author,omitempty"`                                                         // as seen in .config.json
	References           []string `json:"references,omitempty"             yaml:"references,omitempty"`             // as seen in .config.json
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

	// if it's a collection, it's not a single file
	Parsers       []string `json:"parsers,omitempty"       yaml:"parsers,omitempty"`
	PostOverflows []string `json:"postoverflows,omitempty" yaml:"postoverflows,omitempty"`
	Scenarios     []string `json:"scenarios,omitempty"     yaml:"scenarios,omitempty"`
	Collections   []string `json:"collections,omitempty"   yaml:"collections,omitempty"`
}

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

func GetItemMap(itemType string) map[string]Item {
	m, ok := hubIdx[itemType]
	if !ok {
		return nil
	}

	return m
}

// Given a FileInfo, extract the map key. Follow a symlink if necessary
func itemKey(itemPath string) (string, error) {
	f, err := os.Lstat(itemPath)
	if err != nil {
		return "", fmt.Errorf("while performing lstat on %s: %w", itemPath, err)
	}

	if f.Mode()&os.ModeSymlink == 0 {
		// it's not a symlink, so the filename itsef should be the key
		return filepath.Base(itemPath), nil
	}

	// resolve the symlink to hub file
	pathInHub, err := os.Readlink(itemPath)
	if err != nil {
		return "", fmt.Errorf("while reading symlink of %s: %w", itemPath, err)
	}

	author := filepath.Base(filepath.Dir(pathInHub))

	fname := filepath.Base(pathInHub)
	fname = strings.TrimSuffix(fname, ".yaml")
	fname = strings.TrimSuffix(fname, ".yml")

	return fmt.Sprintf("%s/%s", author, fname), nil
}

// GetItemByPath retrieves the item from hubIdx based on the path. To achieve this it will resolve symlink to find associated hub item.
func GetItemByPath(itemType string, itemPath string) (*Item, error) {
	itemKey, err := itemKey(itemPath)
	if err != nil {
		return nil, err
	}

	m := GetItemMap(itemType)
	if m == nil {
		return nil, fmt.Errorf("item type %s doesn't exist", itemType)
	}

	v, ok := m[itemKey]
	if !ok {
		return nil, fmt.Errorf("%s not found in %s", itemKey, itemType)
	}

	return &v, nil
}

func GetItem(itemType string, itemName string) *Item {
	if m, ok := GetItemMap(itemType)[itemName]; ok {
		return &m
	}

	return nil
}

func AddItem(itemType string, item Item) error {
	for _, itype := range ItemTypes {
		if itype == itemType {
			hubIdx[itemType][item.Name] = item
			return nil
		}
	}

	return fmt.Errorf("ItemType %s is unknown", itemType)
}

func DisplaySummary() {
	log.Infof("Loaded %d collecs, %d parsers, %d scenarios, %d post-overflow parsers", len(hubIdx[COLLECTIONS]),
		len(hubIdx[PARSERS]), len(hubIdx[SCENARIOS]), len(hubIdx[PARSERS_OVFLW]))

	if skippedLocal > 0 || skippedTainted > 0 {
		log.Infof("unmanaged items: %d local, %d tainted", skippedLocal, skippedTainted)
	}
}

func GetInstalledItems(itemType string) ([]Item, error) {
	items, ok := hubIdx[itemType]
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

func GetInstalledItemsAsString(itemType string) ([]string, error) {
	items, err := GetInstalledItems(itemType)
	if err != nil {
		return nil, err
	}

	retStr := make([]string, len(items))

	for i, it := range items {
		retStr[i] = it.Name
	}

	return retStr, nil
}
