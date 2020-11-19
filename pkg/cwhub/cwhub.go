package cwhub

import (
	"crypto/sha256"
	"path/filepath"
	"strings"

	//"errors"
	"fmt"
	"io"
	"os"

	"github.com/enescakir/emoji"
	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
)

/*managed configuration types*/
var PARSERS = "parsers"
var PARSERS_OVFLW = "postoverflows"
var SCENARIOS = "scenarios"
var COLLECTIONS = "collections"
var ItemTypes = []string{PARSERS, PARSERS_OVFLW, SCENARIOS, COLLECTIONS}

var HubIdx map[string]map[string]Item

var RawFileURLTemplate = "https://raw.githubusercontent.com/crowdsecurity/hub/%s/%s"
var HubBranch = "master"
var HubIndexFile = ".index.json"

type ItemVersion struct {
	Digest     string
	Deprecated bool
}

//Item can be : parsed, scenario, collection
type Item struct {
	/*descriptive info*/
	Type                 string   `yaml:"type,omitempty"`                         //parser|postoverflows|scenario|collection(|enrich)
	Stage                string   `json:"stage" yaml:"stage,omitempty,omitempty"` //Stage for parser|postoverflow : s00-raw/s01-...
	Name                 string   //as seen in .config.json, usually "author/name"
	FileName             string   //the filename, ie. apache2-logs.yaml
	Description          string   `yaml:"description,omitempty"`            //as seen in .config.json
	Author               string   `json:"author"`                           //as seen in .config.json
	References           []string `yaml:"references,omitempty"`             //as seen in .config.json
	BelongsToCollections []string `yaml:"belongs_to_collections,omitempty"` /*if it's part of collections, track name here*/

	/*remote (hub) infos*/
	RemoteURL  string                 `yaml:"remoteURL,omitempty"`               //the full remote uri of file in http
	RemotePath string                 `json:"path" yaml:"remote_path,omitempty"` //the path relative to git ie. /parsers/stage/author/file.yaml
	RemoteHash string                 `yaml:"hash,omitempty"`                    //the meow
	Version    string                 `json:"version"`                           //the last version
	Versions   map[string]ItemVersion `json:"versions" yaml:"-"`                 //the list of existing versions

	/*local (deployed) infos*/
	LocalPath string `yaml:"local_path,omitempty"` //the local path relative to ${CFG_DIR}
	//LocalHubPath string
	LocalVersion string
	LocalHash    string //the local meow
	Installed    bool
	Downloaded   bool
	UpToDate     bool
	Tainted      bool //has it been locally modified
	Local        bool //if it's a non versioned control one

	/*if it's a collection, it not a single file*/
	Parsers       []string `yaml:"parsers,omitempty"`
	PostOverflows []string `yaml:"postoverflows,omitempty"`
	Scenarios     []string `yaml:"scenarios,omitempty"`
	Collections   []string `yaml:"collections,omitempty"`
}

var skippedLocal = 0
var skippedTainted = 0

/*To be used when reference(s) (is/are) missing in a collection*/
var ReferenceMissingError = errors.New("Reference(s) missing in collection")
var MissingHubIndex = errors.New("hub index can't be found")

// calculate sha256 of a file
func getSHA256(filepath string) (string, error) {
	/* Digest of file */
	f, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("unable to open '%s' : %s", filepath, err.Error())
	}

	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("unable to calculate sha256 of '%s': %s", filepath, err.Error())
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func GetItemMap(itemType string) map[string]Item {
	var m map[string]Item
	var ok bool

	if m, ok = HubIdx[itemType]; !ok {
		return nil
	}
	return m
}

//GetItemByPath retrieves the item from HubIdx based on the path. To achieve this it will resolve symlink to find associated hub item.
func GetItemByPath(itemType string, itemPath string) (*Item, error) {
	/*try to resolve symlink*/
	finalName := ""
	f, err := os.Lstat(itemPath)
	if err != nil {
		return nil, errors.Wrapf(err, "while performing lstat on %s", itemPath)
	}

	if f.Mode()&os.ModeSymlink == 0 {
		/*it's not a symlink, it should be the filename itsef the key*/
		finalName = filepath.Base(itemPath)
	} else {
		/*resolve the symlink to hub file*/
		pathInHub, err := os.Readlink(itemPath)
		if err != nil {
			return nil, errors.Wrapf(err, "while reading symlink of %s", itemPath)
		}
		//extract author from path
		fname := filepath.Base(pathInHub)
		author := filepath.Base(filepath.Dir(pathInHub))
		//trim yaml suffix
		fname = strings.TrimSuffix(fname, ".yaml")
		fname = strings.TrimSuffix(fname, ".yml")
		finalName = fmt.Sprintf("%s/%s", author, fname)
	}

	/*it's not a symlink, it should be the filename itsef the key*/
	if m := GetItemMap(itemType); m != nil {
		if v, ok := m[finalName]; ok {
			return &v, nil
		} else {
			return nil, fmt.Errorf("%s not found in %s", finalName, itemType)
		}
	} else {
		return nil, fmt.Errorf("item type %s doesn't exist", itemType)
	}

}

func GetItem(itemType string, itemName string) *Item {
	if m, ok := GetItemMap(itemType)[itemName]; ok {
		return &m
	}
	return nil
}

func AddItem(itemType string, item Item) error {
	in := false
	for _, itype := range ItemTypes {
		if itype == itemType {
			in = true
		}
	}
	if !in {
		return fmt.Errorf("ItemType %s is unknown", itemType)
	}
	HubIdx[itemType][item.Name] = item
	return nil
}

func DisplaySummary() {
	log.Printf("Loaded %d collecs, %d parsers, %d scenarios, %d post-overflow parsers", len(HubIdx[COLLECTIONS]),
		len(HubIdx[PARSERS]), len(HubIdx[SCENARIOS]), len(HubIdx[PARSERS_OVFLW]))
	if skippedLocal > 0 || skippedTainted > 0 {
		log.Printf("unmanaged items : %d local, %d tainted", skippedLocal, skippedTainted)
	}
}

//returns: human-text, Enabled, Warning, Unmanaged
func ItemStatus(v Item) (string, bool, bool, bool) {
	var Ok, Warning, Managed bool
	var strret string

	if !v.Installed {
		strret = "disabled"
		Ok = false
	} else {
		Ok = true
		strret = "enabled"
	}

	if v.Local {
		Managed = false
		strret += ",local"
	} else {
		Managed = true
	}

	//tainted or out of date
	if v.Tainted {
		Warning = true
		strret += ",tainted"
	} else if !v.UpToDate && !v.Local {
		strret += ",update-available"
		Warning = true
	}
	return strret, Ok, Warning, Managed
}

func GetUpstreamInstalledScenariosAsString() ([]string, error) {
	var retStr []string

	items, err := GetUpstreamInstalledScenarios()
	if err != nil {
		return nil, errors.Wrap(err, "while fetching scenarios")
	}
	for _, it := range items {
		retStr = append(retStr, it.Name)
	}
	return retStr, nil
}

func GetUpstreamInstalledScenarios() ([]Item, error) {
	var retItems []Item

	if _, ok := HubIdx[SCENARIOS]; !ok {
		return nil, fmt.Errorf("no scenarios in HubIdx")
	}
	for _, item := range HubIdx[SCENARIOS] {
		if item.Installed && !item.Tainted {
			retItems = append(retItems, item)
		}
	}
	return retItems, nil
}

//Returns a list of entries for packages : name, status, local_path, local_version, utf8_status (fancy)
func HubStatus(itemType string, name string, listAll bool) []map[string]string {
	if _, ok := HubIdx[itemType]; !ok {
		log.Errorf("type %s doesn't exist", itemType)

		return nil
	}

	var ret []map[string]string
	/*remember, you do it for the user :)*/
	for _, item := range HubIdx[itemType] {
		if name != "" && name != item.Name {
			//user has required a specific name
			continue
		}
		//Only enabled items ?
		if !listAll && !item.Installed {
			continue
		}
		//Check the item status
		status, ok, warning, managed := ItemStatus(item)
		tmp := make(map[string]string)
		tmp["name"] = item.Name
		tmp["status"] = status
		tmp["local_version"] = item.LocalVersion
		tmp["local_path"] = item.LocalPath
		tmp["description"] = item.Description
		if !managed || !item.Installed {
			tmp["utf8_status"] = fmt.Sprintf("%v  %s", emoji.Prohibited, status)
		} else if warning {
			tmp["utf8_status"] = fmt.Sprintf("%v  %s", emoji.Warning, status)
		} else if ok {
			tmp["utf8_status"] = fmt.Sprintf("%v  %s", emoji.CheckMark, status)
		}
		ret = append(ret, tmp)
	}
	return ret
}
