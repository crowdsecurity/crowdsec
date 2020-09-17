package cwhub

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/enescakir/emoji"

	log "github.com/sirupsen/logrus"
)

/*managed configuration types*/
var PARSERS = "parsers"
var PARSERS_OVFLW = "postoverflows"
var SCENARIOS = "scenarios"
var COLLECTIONS = "collections"
var ItemTypes = []string{PARSERS, PARSERS_OVFLW, SCENARIOS, COLLECTIONS}

/*upstream hub info*/
var RawFileURLTemplate = "https://raw.githubusercontent.com/crowdsecurity/hub/%s/%s"
var HubBranch = "master"
var HubIndexFile = ".index.json"

/*global hub state*/
var HubIdx map[string]map[string]Item

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
	} else if !v.UpToDate {
		strret += ",update-available"
		Warning = true
	}
	return strret, Ok, Warning, Managed
}

//Returns a list of entries for packages : name, status, local_path, local_version, utf8_status (fancy)
func HubStatus(itype string, name string, list_all bool) []map[string]string {
	if _, ok := HubIdx[itype]; !ok {
		log.Errorf("type %s doesn't exist", itype)
		return nil
	}

	var mli []map[string]string
	/*remember, you do it for the user :)*/
	for _, v := range HubIdx[itype] {
		if name != "" && name != v.Name {
			//user has required a specific name
			continue
		}
		//Only enabled items ?
		if !list_all && !v.Installed {
			continue
		}
		//Check the item status
		st, ok, warning, managed := ItemStatus(v)
		tmp := make(map[string]string)
		tmp["name"] = v.Name
		tmp["status"] = st
		tmp["local_version"] = v.LocalVersion
		tmp["local_path"] = v.LocalPath
		tmp["description"] = v.Description
		if !managed || !v.Installed {
			tmp["utf8_status"] = fmt.Sprintf("%v  %s", emoji.Prohibited, st)
		} else if warning {
			tmp["utf8_status"] = fmt.Sprintf("%v  %s", emoji.Warning, st)
		} else if ok {
			tmp["utf8_status"] = fmt.Sprintf("%v  %s", emoji.CheckMark, st)
		}
		mli = append(mli, tmp)
	}
	return mli
}
