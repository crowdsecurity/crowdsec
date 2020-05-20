package cwhub

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"path"

	//"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/enescakir/emoji"
	log "github.com/sirupsen/logrus"
)

var PARSERS = "parsers"
var PARSERS_OVFLW = "postoverflows"
var SCENARIOS = "scenarios"
var COLLECTIONS = "collections"

var ItemTypes = []string{PARSERS, PARSERS_OVFLW, SCENARIOS, COLLECTIONS}

var HubIdx map[string]map[string]Item

var Installdir = "/etc/crowdsec/"
var Hubdir = "/etc/crowdsec/cscli/hub/"
var Cfgdir = "/etc/crowdsec/cscli/"

var RawFileURLTemplate = "https://raw.githubusercontent.com/crowdsecurity/hub/master/%s"
var HUB_INDEX_FILE = ".index.json"

type ItemVersion struct {
	Digest     string
	Deprecated bool
}

//Item can be : parsed, scenario, collection
type Item struct {
	/*descriptive info*/
	Type                 string   `yaml:"type,omitempty"`                        //parser|postoverflows|scenario|collection(|enrich)
	Stage                string   `json:"stage" yaml:"type,omitempty,omitempty"` //Stage for parser|postoverflow : s00-raw/s01-...
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

var skippedLocal = 0
var skippedTainted = 0

func parser_visit(path string, f os.FileInfo, err error) error {

	var target Item
	var local bool
	var hubpath string
	var inhub bool
	var fname string
	var ftype string
	var fauthor string
	var stage string
	//we only care about files
	if f == nil || f.IsDir() {
		return nil
	}

	subs := strings.Split(path, "/")

	log.Debugf("path:%s, hubdir:%s, installdir:%s", path, Hubdir, Installdir)
	/*we're in hub (~/.cscli/hub/)*/
	if strings.HasPrefix(path, Hubdir) {
		inhub = true
		//~/.cscli/hub/parsers/s00-raw/crowdsec/skip-pretag.yaml
		//~/.cscli/hub/scenarios/crowdsec/ssh_bf.yaml
		//~/.cscli/hub/profiles/crowdsec/linux.yaml
		if len(subs) < 4 {
			log.Fatalf("path is too short : %s", path)
		}
		fname = subs[len(subs)-1]
		fauthor = subs[len(subs)-2]
		stage = subs[len(subs)-3]
		ftype = subs[len(subs)-4]
		log.Debugf("HUBB check [%s] by [%s] in stage [%s] of type [%s]", fname, fauthor, stage, ftype)

	} else if strings.HasPrefix(path, Installdir) { /*we're in install /etc/crowdsec/<type>/... */
		if len(subs) < 3 {
			log.Fatalf("path is too short : %s", path)
		}
		///etc/.../parser/stage/file.yaml
		///etc/.../postoverflow/stage/file.yaml
		///etc/.../scenarios/scenar.yaml
		///etc/.../collections/linux.yaml //file is empty
		fname = subs[len(subs)-1]
		stage = subs[len(subs)-2]
		ftype = subs[len(subs)-3]
		fauthor = ""
		log.Debugf("INSTALL check [%s] by [%s] in stage [%s] of type [%s]", fname, fauthor, stage, ftype)
	}

	//log.Printf("%s -> name:%s stage:%s", path, fname, stage)
	if stage == SCENARIOS {
		ftype = SCENARIOS
		stage = ""
	} else if stage == COLLECTIONS {
		ftype = COLLECTIONS
		stage = ""
	} else if ftype != PARSERS && ftype != PARSERS_OVFLW /*its a PARSER / PARSER_OVFLW with a stage */ {
		return fmt.Errorf("unknown prefix in %s : fname:%s, fauthor:%s, stage:%s, ftype:%s", path, fname, fauthor, stage, ftype)
	}

	log.Debugf("CORRECTED [%s] by [%s] in stage [%s] of type [%s]", fname, fauthor, stage, ftype)

	/*
		we can encounter 'collections' in the form of a symlink :
		/etc/crowdsec/.../collections/linux.yaml -> ~/.cscli/hub/collections/.../linux.yaml
		when the collection is installed, both files are created
	*/
	//non symlinks are local user files or hub files
	if f.Mode()&os.ModeSymlink == 0 {
		local = true
		skippedLocal++
		log.Debugf("%s isn't a symlink", path)
	} else {
		hubpath, err = os.Readlink(path)
		if err != nil {
			return fmt.Errorf("unable to read symlink of %s", path)
		}
		//the symlink target doesn't exist, user might have remove ~/.cscli/hub/...yaml without deleting /etc/crowdsec/....yaml
		_, err := os.Lstat(hubpath)
		if os.IsNotExist(err) {
			log.Infof("%s is a symlink to %s that doesn't exist, deleting symlink", path, hubpath)
			//remove the symlink
			if err = os.Remove(path); err != nil {
				return fmt.Errorf("failed to unlink %s: %+v", path, err)
			}
			return nil
		}
		log.Debugf("%s points to %s", path, hubpath)
	}

	//if it's not a symlink and not in hub, it's a local file, don't bother
	if local && !inhub {
		log.Debugf("%s is a local file, skip", path)
		skippedLocal++
		//	log.Printf("local scenario, skip.")
		target.Name = fname
		target.Stage = stage
		target.Installed = true
		target.Type = ftype
		target.Local = true
		target.LocalPath = path
		target.UpToDate = true
		x := strings.Split(path, "/")
		target.FileName = x[len(x)-1]

		HubIdx[ftype][fname] = target
		return nil
	}
	//try to find which configuration item it is
	log.Debugf("check [%s] of %s", fname, ftype)

	match := false
	for k, v := range HubIdx[ftype] {
		log.Debugf("check [%s] vs [%s] : %s", fname, v.RemotePath, ftype+"/"+stage+"/"+fname+".yaml")
		if fname != v.FileName {
			log.Debugf("%s != %s (filename)", fname, v.FileName)
			continue
		}
		//wrong stage
		if v.Stage != stage {
			continue
		}
		/*if we are walking hub dir, just mark present files as downloaded*/
		if inhub {
			//wrong author
			if fauthor != v.Author {
				continue
			}
			//wrong file
			if v.Name+".yaml" != fauthor+"/"+fname {
				continue
			}
			if path == Hubdir+"/"+v.RemotePath {
				log.Debugf("marking %s as downloaded", v.Name)
				v.Downloaded = true
			}
		} else {
			//wrong file
			//<type>/<stage>/<author>/<name>.yaml
			if !strings.HasSuffix(hubpath, v.RemotePath) {
				//log.Printf("wrong file %s %s", hubpath, spew.Sdump(v))

				continue
			}
		}
		//wrong hash
		sha, err := getSHA256(path)
		if err != nil {
			log.Fatalf("Failed to get sha of %s : %v", path, err)
		}
		for version, val := range v.Versions {
			if sha != val.Digest {
				//log.Printf("matching filenames, wrong hash %s != %s -- %s", sha, val.Digest, spew.Sdump(v))
				continue
			} else {
				/*we got an exact match, update struct*/
				if !inhub {
					log.Debugf("found exact match for %s, version is %s, latest is %s", v.Name, version, v.Version)
					v.LocalPath = path
					v.LocalVersion = version
					v.Tainted = false
					v.Downloaded = true
					/*if we're walking the hub, present file doesn't means installed file*/
					v.Installed = true
					v.LocalHash = sha
					x := strings.Split(path, "/")
					target.FileName = x[len(x)-1]
				}
				if version == v.Version {
					log.Debugf("%s is up-to-date", v.Name)
					v.UpToDate = true
				} else {
					log.Debugf("%s is outdated", v.Name)
				}
				match = true

			}
		}
		if !match {
			log.Debugf("got tainted match for %s : %s", v.Name, path)
			skippedTainted += 1
			//the file and the stage is right, but the hash is wrong, it has been tainted by user
			if !inhub {
				v.LocalPath = path
				v.Installed = true
			}
			v.UpToDate = false
			v.LocalVersion = "?"
			v.Tainted = true
			v.LocalHash = sha
			x := strings.Split(path, "/")
			target.FileName = x[len(x)-1]

		}
		//update the entry
		HubIdx[ftype][k] = v
		return nil
	}
	log.Infof("Ignoring file %s of type %s", path, ftype)
	return nil
}

func CollecDepsCheck(v *Item) error {
	/*if it's a collection, ensure all the items are installed, or tag it as tainted*/
	if v.Type == COLLECTIONS {
		log.Debugf("checking submembers of %s installed:%t", v.Name, v.Installed)
		var tmp = [][]string{v.Parsers, v.PostOverflows, v.Scenarios, v.Collections}
		for idx, ptr := range tmp {
			ptrtype := ItemTypes[idx]
			for _, p := range ptr {
				if val, ok := HubIdx[ptrtype][p]; ok {
					log.Debugf("check %s installed:%t", val.Name, val.Installed)
					if !v.Installed {
						continue
					}
					if val.Type == COLLECTIONS {
						log.Debugf("collec, recurse.")
						if err := CollecDepsCheck(&val); err != nil {
							return fmt.Errorf("sub collection %s is broken : %s", val.Name, err)
						}
						HubIdx[ptrtype][p] = val
					}

					//propagate the state of sub-items to set
					if val.Tainted {
						v.Tainted = true
						return fmt.Errorf("tainted %s %s, tainted.", ptrtype, p)
					} else if !val.Installed && v.Installed {
						v.Tainted = true
						return fmt.Errorf("missing %s %s, tainted.", ptrtype, p)
					} else if !val.UpToDate {
						v.UpToDate = false
						return fmt.Errorf("outdated %s %s", ptrtype, p)
					}
					val.BelongsToCollections = append(val.BelongsToCollections, v.Name)
					HubIdx[ptrtype][p] = val
					log.Debugf("checking for %s - tainted:%t uptodate:%t", p, v.Tainted, v.UpToDate)
				} else {
					log.Fatalf("Referred %s %s in collection %s doesn't exist.", ptrtype, p, v.Name)
				}
			}
		}
	}
	return nil
}

/* Updates the infos from HubInit() with the local state */
func LocalSync() error {
	skippedLocal = 0
	skippedTainted = 0
	/*For each, scan PARSERS, PARSERS_OVFLW, SCENARIOS and COLLECTIONS last*/
	for _, scan := range ItemTypes {
		/*Scan install and Hubdir to get local status*/
		for _, dir := range []string{Installdir, Hubdir} {
			//walk the user's directory
			err := filepath.Walk(dir+"/"+scan, parser_visit)
			if err != nil {
				return err
			}
		}
	}

	for k, v := range HubIdx[COLLECTIONS] {
		if err := CollecDepsCheck(&v); err != nil {
			log.Infof("dependency issue %s : %s", v.Name, err)
		}
		HubIdx[COLLECTIONS][k] = v
	}
	return nil
}

func GetHubIdx() error {

	bidx, err := ioutil.ReadFile(Cfgdir + "/.index.json")
	if err != nil {
		log.Fatalf("Unable to read downloaded index : %v. Please run update", err)
	}
	ret, err := LoadPkgIndex(bidx)
	if err != nil {
		log.Fatalf("Unable to load existing index : %v.", err)
	}
	HubIdx = ret
	if err := LocalSync(); err != nil {
		log.Fatalf("Failed to sync Hub index with local deployment : %v", err)
	}
	return nil
}

func UpdateHubIdx() error {
	bidx, err := DownloadHubIdx()
	if err != nil {
		log.Fatalf("Unable to download index : %v.", err)
	}
	ret, err := LoadPkgIndex(bidx)
	if err != nil {
		log.Fatalf("Unable to load freshly downloaded index : %v.", err)
	}
	HubIdx = ret
	if err := LocalSync(); err != nil {
		log.Fatalf("Failed to sync Hub index with local deployment : %v", err)
	}
	return nil
}

func DownloadHubIdx() ([]byte, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(RawFileURLTemplate, HUB_INDEX_FILE), nil)
	if err != nil {
		log.Errorf("failed request : %s", err)
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf("failed request Do : %s", err)
		return nil, err
	}
	if resp.StatusCode != 200 {
		log.Errorf("got code %d while requesting %s, abort", resp.StatusCode,
			fmt.Sprintf(RawFileURLTemplate, HUB_INDEX_FILE))
		return nil, fmt.Errorf("bad http code")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("failed request reqd: %s", err)
		return nil, err
	}
	//os.Remove(path.Join(configFolder, GitIndexFile))
	file, err := os.OpenFile(path.Join(Cfgdir, "/.index.json"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)

	if err != nil {
		log.Fatalf(err.Error())
	}
	defer file.Close()

	wsize, err := file.WriteString(string(body))
	if err != nil {
		log.Fatalf(err.Error())
	}
	log.Infof("Wrote new %d bytes index to %s", wsize, path.Join(Cfgdir, "/.index.json"))
	return body, nil
}

func DisplaySummary() {
	log.Printf("Loaded %d collecs, %d parsers, %d scenarios, %d post-overflow parsers", len(HubIdx[COLLECTIONS]),
		len(HubIdx[PARSERS]), len(HubIdx[SCENARIOS]), len(HubIdx[PARSERS_OVFLW]))
	if skippedLocal > 0 || skippedTainted > 0 {
		log.Printf("unmanaged items : %d local, %d tainted", skippedLocal, skippedTainted)
	}
}

/*LoadPkgIndex loads a local .index.json file and returns the map of parsers/scenarios/collections associated*/
func LoadPkgIndex(buff []byte) (map[string]map[string]Item, error) {
	var err error
	var RawIndex map[string]map[string]Item

	if err = json.Unmarshal(buff, &RawIndex); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index : %v", err)
	}

	/*Iterate over the different types to complete struct */
	for _, itemType := range ItemTypes {
		/*complete struct*/
		for idx, item := range RawIndex[itemType] {
			item.Name = idx
			item.Type = itemType
			x := strings.Split(item.RemotePath, "/")
			item.FileName = x[len(x)-1]
			RawIndex[itemType][idx] = item
			/*if it's a collection, check its sub-items are present*/
			//XX should be done later
			if itemType == COLLECTIONS {
				var tmp = [][]string{item.Parsers, item.PostOverflows, item.Scenarios, item.Collections}
				for idx, ptr := range tmp {
					ptrtype := ItemTypes[idx]
					for _, p := range ptr {
						if _, ok := RawIndex[ptrtype][p]; !ok {
							log.Errorf("Referred %s %s in collection %s doesn't exist.", ptrtype, p, item.Name)
						}
					}
				}
			}
		}
	}

	return RawIndex, nil
}

//DisableItem to disable an item managed by the hub, removes the symlink
func DisableItem(target Item, tdir string, hdir string, purge bool) (Item, error) {
	syml := tdir + "/" + target.Type + "/" + target.Stage + "/" + target.FileName
	if target.Local {
		return target, fmt.Errorf("%s isn't managed by hub. Please delete manually", target.Name)
	}

	var err error
	/*for a COLLECTIONS, disable sub-items*/
	if target.Type == COLLECTIONS {
		var tmp = [][]string{target.Parsers, target.PostOverflows, target.Scenarios, target.Collections}
		for idx, ptr := range tmp {
			ptrtype := ItemTypes[idx]
			for _, p := range ptr {
				if val, ok := HubIdx[ptrtype][p]; ok {
					HubIdx[ptrtype][p], err = DisableItem(val, Installdir, Hubdir, false)
					if err != nil {
						log.Errorf("Encountered error while disabling %s %s : %s.", ptrtype, p, err)
					}
				} else {
					log.Errorf("Referred %s %s in collection %s doesn't exist.", ptrtype, p, target.Name)
				}
			}
		}

	}

	stat, err := os.Lstat(syml)
	if os.IsNotExist(err) {
		log.Warningf("%s (%s) doesn't exist, can't disable", target.Name, syml)
		//return target, nil //fmt.Errorf("'%s' doesn't exist", syml)
	} else {
		//if it's managed by hub, it's a symlink to Hubdir / ...
		if stat.Mode()&os.ModeSymlink == 0 {
			log.Warningf("%s (%s) isn't a symlink, can't disable", target.Name, syml)
			return target, fmt.Errorf("%s isn't managed by hub", target.Name)
		}
		hubpath, err := os.Readlink(syml)
		if err != nil {
			return target, fmt.Errorf("unable to read symlink of %s (%s)", target.Name, syml)
		}
		if hubpath != filepath.Clean(hdir+"/"+target.RemotePath) {
			log.Warningf("%s (%s) isn't a symlink to %s", target.Name, syml, filepath.Clean(hdir+"/"+target.RemotePath))
			return target, fmt.Errorf("%s isn't managed by hub", target.Name)
		}

		//remove the symlink
		if err = os.Remove(syml); err != nil {
			return target, fmt.Errorf("failed to unlink %s: %+v", syml, err)
		}
		log.Infof("Removed symlink [%s] : %s", target.Name, syml)
	}
	target.Installed = false

	if purge {
		hubpath := hdir + "/" + target.RemotePath
		//if purge, disable hub file
		if err = os.Remove(hubpath); err != nil {
			return target, fmt.Errorf("failed to purge hub file %s: %+v", hubpath, err)
		}
		target.Downloaded = false
		log.Infof("Removed source file [%s] : %s", target.Name, hubpath)
	}
	return target, nil
}

func EnableItem(target Item, tdir string, hdir string) (Item, error) {
	parent_dir := filepath.Clean(tdir + "/" + target.Type + "/" + target.Stage + "/")
	/*create directories if needed*/
	if target.Installed {
		if target.Tainted {
			return target, fmt.Errorf("%s is tainted, won't enable unless --force", target.Name)
		}
		if target.Local {
			return target, fmt.Errorf("%s is local, won't enable", target.Name)
		}
		if target.UpToDate {
			log.Debugf("%s is installed and up-to-date, skip.", target.Name)
			return target, nil
		}
	}
	if _, err := os.Stat(parent_dir); os.IsNotExist(err) {
		log.Printf("%s doesn't exist, create", parent_dir)
		if err := os.MkdirAll(parent_dir, os.ModePerm); err != nil {
			return target, fmt.Errorf("unable to create parent directories")
		}
	}
	if _, err := os.Lstat(parent_dir + "/" + target.FileName); os.IsNotExist(err) {
		/*install sub-items if it's a collection*/
		if target.Type == COLLECTIONS {
			var tmp = [][]string{target.Parsers, target.PostOverflows, target.Scenarios, target.Collections}
			for idx, ptr := range tmp {
				ptrtype := ItemTypes[idx]
				for _, p := range ptr {
					if val, ok := HubIdx[ptrtype][p]; ok {
						HubIdx[ptrtype][p], err = EnableItem(val, Installdir, Hubdir)
						if err != nil {
							log.Errorf("Encountered error while installing sub-item %s %s : %s.", ptrtype, p, err)
							return target, fmt.Errorf("encountered error while install %s for %s, abort.", val.Name, target.Name)
						}
					} else {
						//log.Errorf("Referred %s %s in collection %s doesn't exist.", ptrtype, p, target.Name)
						return target, fmt.Errorf("required %s %s of %s doesn't exist, abort.", ptrtype, p, target.Name)
					}
				}
			}
		}
		//tdir+target.RemotePath
		srcPath, err := filepath.Abs(hdir + "/" + target.RemotePath)
		if err != nil {
			return target, fmt.Errorf("failed to resolve %s : %s", hdir+"/"+target.RemotePath, err)
		}
		dstPath, err := filepath.Abs(parent_dir + "/" + target.FileName)
		if err != nil {
			return target, fmt.Errorf("failed to resolve %s : %s", parent_dir+"/"+target.FileName, err)
		}
		err = os.Symlink(srcPath, dstPath)
		if err != nil {
			log.Fatalf("Failed to symlink %s to %s : %v", srcPath, dstPath, err)
			return target, fmt.Errorf("failed to symlink %s to %s", srcPath, dstPath)
		}
		log.Printf("Enabled %s : %s", target.Type, target.Name)
	} else {
		log.Printf("%s already exists.", parent_dir+"/"+target.FileName)
		return target, nil
	}
	target.Installed = true
	return target, nil
}

func DownloadLatest(target Item, tdir string, overwrite bool) (Item, error) {
	var err error
	log.Debugf("Downloading %s %s", target.Type, target.Name)
	if target.Type == COLLECTIONS {
		var tmp = [][]string{target.Parsers, target.PostOverflows, target.Scenarios, target.Collections}
		for idx, ptr := range tmp {
			ptrtype := ItemTypes[idx]
			for _, p := range ptr {
				if val, ok := HubIdx[ptrtype][p]; ok {
					log.Debugf("Download %s sub-item : %s %s", target.Name, ptrtype, p)
					//recurse as it's a collection
					if ptrtype == COLLECTIONS {
						log.Debugf("collection, recurse")
						HubIdx[ptrtype][p], err = DownloadLatest(val, tdir, overwrite)
						if err != nil {
							log.Errorf("Encountered error while downloading sub-item %s %s : %s.", ptrtype, p, err)
							return target, fmt.Errorf("encountered error while downloading %s for %s, abort", val.Name, target.Name)
						}
					}
					HubIdx[ptrtype][p], err = DownloadItem(val, tdir, overwrite)
					if err != nil {
						log.Errorf("Encountered error while downloading sub-item %s %s : %s.", ptrtype, p, err)
						return target, fmt.Errorf("encountered error while downloading %s for %s, abort", val.Name, target.Name)
					}
				} else {
					//log.Errorf("Referred %s %s in collection %s doesn't exist.", ptrtype, p, target.Name)
					return target, fmt.Errorf("required %s %s of %s doesn't exist, abort", ptrtype, p, target.Name)
				}
			}
		}
		target, err = DownloadItem(target, tdir, overwrite)
		if err != nil {
			return target, fmt.Errorf("failed to download item : %s", err)
		}
	} else {
		return DownloadItem(target, tdir, overwrite)
	}
	return target, nil
}

func DownloadItem(target Item, tdir string, overwrite bool) (Item, error) {

	/*if user didn't --force, don't overwrite local, tainted, up-to-date files*/
	if !overwrite {
		if target.Tainted {
			log.Debugf("%s : tainted, not updated", target.Name)
			return target, nil
		}
		if target.UpToDate {
			log.Debugf("%s : up-to-date, not updated", target.Name)
			return target, nil
		}
	}

	//log.Infof("Downloading %s to %s", target.Name, tdir)
	req, err := http.NewRequest("GET", fmt.Sprintf(RawFileURLTemplate, target.RemotePath), nil)
	if err != nil {
		log.Errorf("%s : request creation failed : %s", target.Name, err)
		return target, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf("%s : request failed : %s", target.Name, err)
		return target, err
	}
	if resp.StatusCode != 200 {
		log.Errorf("%s : non 200 response : %d", target.Name, resp.StatusCode)
		return target, fmt.Errorf("bad http code")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("%s : failed request read: %s", target.Name, err)
		return target, err
	}
	h := sha256.New()
	if _, err := h.Write([]byte(body)); err != nil {
		return target, fmt.Errorf("%s : failed to write : %s", target.Name, err)
	}
	meow := fmt.Sprintf("%x", h.Sum(nil))
	if meow != target.Versions[target.Version].Digest {
		log.Errorf("Downloaded version doesn't match index, please 'hub update'")
		return target, fmt.Errorf("invalid download hash")
	}
	//all good, install
	//check if parent dir exists
	tmpdirs := strings.Split(tdir+"/"+target.RemotePath, "/")
	parent_dir := strings.Join(tmpdirs[:len(tmpdirs)-1], "/")

	/*check dir*/
	if _, err = os.Stat(parent_dir); os.IsNotExist(err) {
		log.Debugf("%s doesn't exist, create", parent_dir)
		if err := os.MkdirAll(parent_dir, os.ModePerm); err != nil {
			return target, fmt.Errorf("unable to create parent directories")
		}
	}
	/*check actual file*/
	if _, err = os.Stat(tdir + "/" + target.RemotePath); !os.IsNotExist(err) {
		log.Warningf("%s : overwrite", target.Name)
		log.Debugf("target: %s/%s", tdir, target.RemotePath)
	} else {
		log.Infof("%s : OK", target.Name)
	}

	f, err := os.OpenFile(tdir+"/"+target.RemotePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return target, fmt.Errorf("failed to open destination file %s : %v", tdir+"/"+target.RemotePath, err)
	}
	defer f.Close()
	_, err = f.WriteString(string(body))
	if err != nil {
		return target, fmt.Errorf("failed to write destination file %s : %v", tdir+"/"+target.RemotePath, err)
	}
	target.Downloaded = true
	target.Tainted = false
	target.UpToDate = true

	return target, nil
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
	if list_all {
		log.Printf("only enabled ones")
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
