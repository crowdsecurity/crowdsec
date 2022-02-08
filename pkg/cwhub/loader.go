package cwhub

import (
	"encoding/json"
	//"errors"
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
	"golang.org/x/mod/semver"

	//"log"

	"os"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	log "github.com/sirupsen/logrus"
)

/*the walk function can't receive extra args*/
var hubdir, installdir, datadir string

func visitDiscard(path string, f os.FileInfo) (string, bool, error) {
	//return path, false, nil
	path, err := filepath.Abs(path)
	if err != nil {
		return path, true, err
	}
	//we only care about files
	if f == nil || f.IsDir() {
		return path, true, nil
	}
	return path, false, nil
}

func hubdirVisit(path string, f os.FileInfo, err error) error {

	if err != nil {
		log.Warningf("error visiting %s", err)
	}
	allowed_extensions := map[string]bool{".yaml": true, ".yml": true}
	/*only interested by yaml files */
	path, discard, err := visitDiscard(path, f)
	if err != nil {
		return err
	}
	if discard {
		return nil
	}
	if !allowed_extensions[filepath.Ext(path)] {
		log.Debugf("discarding %s : not a yaml file", path)
		return nil
	}
	//extract components from path :
	//.../hub/parsers/s00-raw/crowdsec/skip-pretag.yaml
	//.../hub/scenarios/crowdsec/ssh_bf.yaml
	//.../hub/profiles/crowdsec/linux.yaml
	path_components := strings.Split(path, string(filepath.Separator))

	if len(path_components) < 4 {
		log.Fatalf("path is too short : %s (%d)", path, len(path_components))
	}
	fname := path_components[len(path_components)-1]
	fauthor := path_components[len(path_components)-2]
	fstage := path_components[len(path_components)-3]
	ftype := path_components[len(path_components)-4]

	log.Tracef("%s : stage:%s ftype:%s", path, fstage, ftype)

	if ftype == DATA_FILES {
		return fmt.Errorf("unexpected data file in hub : %s", path)
	}

	// correct the stage and type for non-stage stuff.
	if fstage == SCENARIOS {
		ftype = SCENARIOS
		fstage = ""
	} else if fstage == COLLECTIONS {
		ftype = COLLECTIONS
		fstage = ""
	} else if ftype != PARSERS && ftype != PARSERS_OVFLW { /*its a PARSER / PARSER_OVFLW with a stage */
		return fmt.Errorf("unknown configuration type for file '%s'", path)
	}

	log.Tracef("CORRECTED [%s] by [%s] in stage [%s] of type [%s]", fname, fauthor, fstage, ftype)

	//in the hub, we don't expect symlinks
	if f.Mode()&os.ModeSymlink != 0 {
		log.Warningf("%s in the hub is a symlink, this isn't expected", path)
	}
	//try to find which configuration item it is
	log.Tracef("check [%s] of %s", fname, ftype)

	for itemName, item := range hubIdx[ftype] {
		log.Tracef("check [%s] vs [%s] : %s/%s/%s", fname, item.RemotePath, ftype, fstage, fname)
		if !item.compareFile(fname, fstage, fauthor, path) {
			continue
		}
		//we're in the hub, mark the file as present and downloaded
		if path == hubdir+"/"+item.RemotePath { //
			log.Tracef("marking %s as downloaded", item.Name)
			item.Downloaded = true
		}

		version, sha, uptodate, err := item.getVersion(path)
		if err != nil {
			return errors.Wrapf(err, "while getting version of %s", path)
		}

		if version == "" {
			log.Debugf("got tainted match for %s : %s", item.Name, path)
			skippedTainted += 1
			item.UpToDate = uptodate
			item.LocalVersion = "?"
			item.Tainted = true
			item.LocalHash = sha
		} else {
			item.UpToDate = uptodate
		}
		//if it was not present, update the index (it's the first time we're seeing this item. Might be downloaded and not installed)
		if _, ok := hubIdx[ftype][itemName]; !ok {
			hubIdx[ftype][itemName] = item
		}
		return nil
	}
	log.Infof("File %s found in hub directory wasn't found in the hub index, ignoring it", path)
	return nil
}

func configdirVisit(path string, f os.FileInfo, err error) error {

	if err != nil {
		log.Warningf("error visiting %s", err)
	}
	allowed_extensions := map[string]bool{".yaml": true, ".yml": true}
	/*only interested by yaml files */
	path, discard, err := visitDiscard(path, f)
	if err != nil {
		return err
	}
	if discard {
		return nil
	}
	if !allowed_extensions[filepath.Ext(path)] {
		log.Debugf("discarding %s : not a yaml file", path)
		return nil
	}
	path_components := strings.Split(path, string(filepath.Separator))

	if len(path_components) < 3 {
		log.Fatalf("path is too short : %s (%d)", path, len(path_components))
	}
	///.../config/parser/stage/file.yaml
	///.../config/postoverflow/stage/file.yaml
	///.../config/scenarios/scenar.yaml
	///.../config/collections/linux.yaml //file is empty
	fname := path_components[len(path_components)-1]
	fstage := path_components[len(path_components)-2]
	ftype := path_components[len(path_components)-3]

	if ftype == DATA_FILES {
		return fmt.Errorf("unexpected data file in install directory : %s", path)
	}

	log.Tracef("stage:%s ftype:%s", fstage, ftype)

	// correct the stage and type for non-stage stuff.
	if fstage == SCENARIOS {
		ftype = SCENARIOS
		fstage = ""
	} else if fstage == COLLECTIONS {
		ftype = COLLECTIONS
		fstage = ""
	} else if ftype != PARSERS && ftype != PARSERS_OVFLW { /*its a PARSER / PARSER_OVFLW with a stage */
		return fmt.Errorf("unknown configuration type for file '%s'", path)
	}
	log.Tracef("CORRECTED [%s] in stage [%s] of type [%s]", fname, fstage, ftype)

	//non symlinks are local user files or hub files or data files
	if f.Mode()&os.ModeSymlink == 0 {
		log.Tracef("%s isn't a symlink", path)
		local_item := Item{}
		log.Tracef("%s is a local file, skip", path)
		skippedLocal++
		local_item.Name = fname
		local_item.Stage = fstage
		local_item.Installed = true
		local_item.Type = ftype
		local_item.Local = true
		local_item.LocalPath = path
		local_item.UpToDate = true
		x := strings.Split(path, string(filepath.Separator))
		local_item.FileName = x[len(x)-1]
		hubIdx[ftype][fname] = local_item
		return nil

	}
	hubpath, err := os.Readlink(path)
	if err != nil {
		return fmt.Errorf("unable to read symlink of %s", path)
	}
	//the symlink target doesn't exist, user might have removed hub directory without deleting /etc/crowdsec/....yaml
	_, err = os.Lstat(hubpath)
	if os.IsNotExist(err) {
		log.Infof("%s is a symlink to %s that doesn't exist, deleting symlink", path, hubpath)
		//remove the symlink
		if err = os.Remove(path); err != nil {
			return fmt.Errorf("failed to unlink %s: %+v", path, err)
		}
		return nil
	}

	//try to get the matching item version
	for itemName, item := range hubIdx[ftype] { // eg ftype = "collections", k = crowdsecurity/nginx, v is an Item struct
		if !item.compareFile(fname, fstage, "", path) {
			continue
		}
		log.Tracef("check [%s] vs [%s] : %s", fname, item.RemotePath, ftype+"/"+fstage+"/"+fname+".yaml")
		version, sha, uptodate, err := item.getVersion(path)
		if err != nil {
			return errors.Wrapf(err, "while getting version of %s", path)
		}
		item.LocalPath = path
		item.Installed = true
		item.LocalHash = sha
		log.Debugf("found exact match for %s : version is %s (up-to-date:%t)", path, version, uptodate)
		/*we found the matching item, update it*/
		if version != "" {
			item.LocalVersion = version
			item.Tainted = false
			item.Downloaded = true
			item.UpToDate = uptodate
		} else {
			skippedTainted += 1
			//the file and the stage is right, but the hash is wrong, it has been tainted by user
			item.UpToDate = false
			item.LocalVersion = "?"
			item.Tainted = true
		}
		hubIdx[ftype][itemName] = item
		return nil
	}
	log.Warningf("File %s found in install directory wasn't accounted for : not a symlink to hub, not a local file", path)
	return nil
}

func datadirVisit(path string, f os.FileInfo, err error) error {

	if err != nil {
		log.Warningf("error visiting %s", err)
	}

	/*only interested by yaml files */
	path, discard, err := visitDiscard(path, f)
	if err != nil {
		return err
	}
	if discard {
		return nil
	}

	path_components := strings.Split(path, string(filepath.Separator))

	if len(path_components) < 2 {
		log.Fatalf("path is too short : %s (%d)", path, len(path_components))
	}
	fname := path_components[len(path_components)-1]
	fauthor := path_components[len(path_components)-2]
	ftype := DATA_FILES

	log.Tracef("CORRECTED [%s] by [%s] of type [%s]", fname, fauthor, ftype)

	//non symlinks are local user files or hub files or data files
	if f.Mode()&os.ModeSymlink != 0 {
		log.Warningf("%s is a symlink, that's unexpected (but can be ok)", path)
		final_path, err := os.Readlink(path)
		if err != nil {
			return fmt.Errorf("unable to read symlink of %s", path)
		}
		//the symlink target doesn't exist, user might have removed ~/.hub/hub/...yaml without deleting /etc/crowdsec/....yaml
		_, err = os.Lstat(path)
		if os.IsNotExist(err) {
			log.Infof("%s is a symlink to %s that doesn't exist, deleting symlink", path, final_path)
			if err = os.Remove(path); err != nil {
				return fmt.Errorf("failed to unlink %s: %+v", path, err)
			}
			return nil
		}
	}

	//try to find which configuration item it is
	log.Tracef("check [%s] of %s", fname, ftype)

	for itemName, item := range hubIdx[ftype] { // eg ftype = "collections", k = crowdsecurity/nginx, v is an Item struct
		log.Tracef("check [%s] vs [%s]", fname, item.RemotePath)
		if !item.compareFile(fname, "", fauthor, path) {
			continue
		}

		version, sha, uptodate, err := item.getVersion(path)
		if err != nil {
			return errors.Wrapf(err, "while getting version of %s", path)
		}
		item.LocalPath = path
		item.Installed = true
		item.LocalHash = sha
		log.Debugf("DATA [%s] found exact match for %s : version is %s (up-to-date:%t)", itemName, path, version, uptodate)
		if version == "" {
			skippedTainted += 1
			item.UpToDate = uptodate
			item.LocalVersion = "?"
			item.Tainted = true
			item.LocalHash = sha
		} else {
			item.UpToDate = uptodate
			item.LocalVersion = version
			item.LocalHash = sha
		}
		hubIdx[ftype][itemName] = item
		return nil
	}
	log.Debugf("Ignoring file %s of type %s", path, ftype)

	return nil
}

func CollecDepsCheck(v *Item) error {

	if GetVersionStatus(v) != 0 { //not up-to-date
		log.Debugf("%s dependencies not checked : not up-to-date", v.Name)
		return nil
	}

	/*if it's a collection, ensure all the items are installed, or tag it as tainted*/
	if v.Type == COLLECTIONS {
		log.Tracef("checking submembers of %s installed:%t", v.Name, v.Installed)
		var tmp = [][]string{v.Parsers, v.PostOverflows, v.Scenarios, v.Collections}
		for idx, ptr := range tmp {
			ptrtype := ItemTypes[idx]
			for _, p := range ptr {
				val, ok := hubIdx[ptrtype][p]
				if !ok {
					log.Fatalf("Referred %s %s in collection %s doesn't exist.", ptrtype, p, v.Name)
				}
				log.Tracef("check %s installed:%t", val.Name, val.Installed)
				if !v.Installed {
					continue
				}
				if val.Type == COLLECTIONS {
					log.Tracef("collec, recurse.")
					if err := CollecDepsCheck(&val); err != nil {
						return fmt.Errorf("sub collection %s warning : %s", val.Name, err)
					}
					hubIdx[ptrtype][p] = val
				}

				//propagate the state of sub-items to set
				if val.Tainted {
					v.Tainted = true
					return fmt.Errorf("tainted %s %s, tainted.", ptrtype, p)
				}
				if !val.Installed && v.Installed {
					v.Tainted = true
					return fmt.Errorf("missing %s %s, tainted.", ptrtype, p)
				}
				if !val.UpToDate {
					v.UpToDate = false
					return fmt.Errorf("outdated %s %s", ptrtype, p)
				}
				skip := false
				for idx := range val.BelongsToCollections {
					if val.BelongsToCollections[idx] == v.Name {
						skip = true
					}
				}
				if !skip {
					val.BelongsToCollections = append(val.BelongsToCollections, v.Name)
				}
				hubIdx[ptrtype][p] = val
				log.Tracef("checking for %s - tainted:%t uptodate:%t", p, v.Tainted, v.UpToDate)
			}
		}
	}
	return nil
}

func SyncDir(hub *csconfig.Hub, dir string) (error, []string) {
	hubdir = hub.HubDir
	installdir = hub.ConfigDir
	datadir = hub.DataDir
	warnings := []string{}

	//data_dir is quite simple : there is no collections and such
	if dir == hub.DataDir {
		var cpath string
		var err error
		cpath, err = filepath.Abs(hub.DataDir)
		if err != nil {
			log.Errorf("failed %s : %s", cpath, err)
		}
		err = filepath.Walk(cpath, datadirVisit)
		return err, warnings
	}

	/*For each, scan PARSERS, PARSERS_OVFLW, DATA_FILES, SCENARIOS and COLLECTIONS last*/
	for _, scan := range ItemTypes {
		var cpath string
		var err error

		cpath, err = filepath.Abs(fmt.Sprintf("%s/%s", dir, scan))
		if err != nil {
			log.Errorf("failed %s : %s", cpath, err)
		}

		switch dir {
		case hub.HubDir:
			err = filepath.Walk(cpath, hubdirVisit)
		case hub.ConfigDir:
			err = filepath.Walk(cpath, configdirVisit)
		default:
			log.Fatalf("unexpected dir %s", dir)
		}
		if err != nil {
			return err, warnings
		}
	}

	for k, v := range hubIdx[COLLECTIONS] {
		if !v.Installed {
			continue
		}
		versStat := GetVersionStatus(&v)
		if versStat == 0 { //latest
			if err := CollecDepsCheck(&v); err != nil {
				warnings = append(warnings, fmt.Sprintf("dependency of %s : %s", v.Name, err))
				hubIdx[COLLECTIONS][k] = v
			}
		} else if versStat == 1 { //not up-to-date
			warnings = append(warnings, fmt.Sprintf("update for collection %s available (currently:%s, latest:%s)", v.Name, v.LocalVersion, v.Version))
		} else { //version is higher than the highest available from hub?
			warnings = append(warnings, fmt.Sprintf("collection %s is in the future (currently:%s, latest:%s)", v.Name, v.LocalVersion, v.Version))
		}
		log.Debugf("installed (%s) - status:%d | installed:%s | latest : %s | full : %+v", v.Name, semver.Compare("v"+v.Version, "v"+v.LocalVersion), v.LocalVersion, v.Version, v.Versions)
	}
	return nil, warnings
}

/* Updates the infos from HubInit() with the local state */
func LocalSync(hub *csconfig.Hub) (error, []string) {
	skippedLocal = 0
	skippedTainted = 0

	err, warnings := SyncDir(hub, hub.ConfigDir)
	if err != nil {
		return fmt.Errorf("failed to scan %s : %s", hub.ConfigDir, err), warnings
	}
	err, _ = SyncDir(hub, hub.HubDir)
	if err != nil {
		return fmt.Errorf("failed to scan %s : %s", hub.HubDir, err), warnings
	}
	err, _ = SyncDir(hub, hub.DataDir)
	if err != nil {
		return fmt.Errorf("failed to scan %s : %s", hub.DataDir, err), warnings
	}
	return nil, warnings
}

func GetHubIdx(hub *csconfig.Hub) error {
	if hub == nil {
		return fmt.Errorf("no configuration found for hub")
	}
	log.Debugf("loading hub idx %s", hub.HubIndexFile)
	bidx, err := ioutil.ReadFile(hub.HubIndexFile)
	if err != nil {
		return errors.Wrap(err, "unable to read index file")
	}
	ret, err := LoadPkgIndex(bidx)
	if err != nil {
		if !errors.Is(err, ReferenceMissingError) {
			log.Fatalf("Unable to load existing index : %v.", err)
		}
		return err
	}
	hubIdx = ret
	err, _ = LocalSync(hub)
	if err != nil {
		log.Fatalf("Failed to sync Hub index with local deployment : %v", err)
	}
	return nil
}

/*LoadPkgIndex loads a local .index.json file and returns the map of parsers/scenarios/collections associated*/
func LoadPkgIndex(buff []byte) (map[string]map[string]Item, error) {
	var err error
	var RawIndex map[string]map[string]Item
	var missingItems []string

	if err = json.Unmarshal(buff, &RawIndex); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index : %v", err)
	}

	log.Debugf("%d item types in hub index", len(ItemTypes))
	/*Iterate over the different types to complete struct */
	for _, itemType := range ItemTypes {
		/*complete struct*/
		log.Tracef("%d item", len(RawIndex[itemType]))
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
							missingItems = append(missingItems, p)
						}
					}
				}
			}
		}
	}
	if len(missingItems) > 0 {
		return RawIndex, fmt.Errorf("%q : %w", missingItems, ReferenceMissingError)
	}

	return RawIndex, nil
}
