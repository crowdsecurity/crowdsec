package cwhub

import (
	"encoding/json"
	//"errors"
	"fmt"
	"io/ioutil"
	"sort"

	"github.com/pkg/errors"
	"golang.org/x/mod/semver"

	//"log"

	"os"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	log "github.com/sirupsen/logrus"
)

/*the walk/parser_visit function can't receive extra args*/
var hubdir, installdir string

func parser_visit(path string, f os.FileInfo, err error) error {

	var target Item
	var local bool
	var hubpath string
	var inhub bool
	var fname string
	var ftype string
	var fauthor string
	var stage string

	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	//we only care about files
	if f == nil || f.IsDir() {
		return nil
	}
	//we only care about yaml files
	if !strings.HasSuffix(f.Name(), ".yaml") && !strings.HasSuffix(f.Name(), ".yml") {
		return nil
	}

	subs := strings.Split(path, "/")

	log.Tracef("path:%s, hubdir:%s, installdir:%s", path, hubdir, installdir)
	/*we're in hub (~/.hub/hub/)*/
	if strings.HasPrefix(path, hubdir) {
		log.Tracef("in hub dir")
		inhub = true
		//.../hub/parsers/s00-raw/crowdsec/skip-pretag.yaml
		//.../hub/scenarios/crowdsec/ssh_bf.yaml
		//.../hub/profiles/crowdsec/linux.yaml
		if len(subs) < 4 {
			log.Fatalf("path is too short : %s (%d)", path, len(subs))
		}
		fname = subs[len(subs)-1]
		fauthor = subs[len(subs)-2]
		stage = subs[len(subs)-3]
		ftype = subs[len(subs)-4]
	} else if strings.HasPrefix(path, installdir) { /*we're in install /etc/crowdsec/<type>/... */
		log.Tracef("in install dir")
		if len(subs) < 3 {
			log.Fatalf("path is too short : %s (%d)", path, len(subs))
		}
		///.../config/parser/stage/file.yaml
		///.../config/postoverflow/stage/file.yaml
		///.../config/scenarios/scenar.yaml
		///.../config/collections/linux.yaml //file is empty
		fname = subs[len(subs)-1]
		stage = subs[len(subs)-2]
		ftype = subs[len(subs)-3]
		fauthor = ""
	} else {
		return fmt.Errorf("File '%s' is not from hub '%s' nor from the configuration directory '%s'", path, hubdir, installdir)
	}

	log.Tracef("stage:%s ftype:%s", stage, ftype)
	//log.Printf("%s -> name:%s stage:%s", path, fname, stage)
	if stage == SCENARIOS {
		ftype = SCENARIOS
		stage = ""
	} else if stage == COLLECTIONS {
		ftype = COLLECTIONS
		stage = ""
	} else if ftype != PARSERS && ftype != PARSERS_OVFLW /*its a PARSER / PARSER_OVFLW with a stage */ {
		return fmt.Errorf("unknown configuration type for file '%s'", path)
	}

	log.Tracef("CORRECTED [%s] by [%s] in stage [%s] of type [%s]", fname, fauthor, stage, ftype)

	/*
		we can encounter 'collections' in the form of a symlink :
		/etc/crowdsec/.../collections/linux.yaml -> ~/.hub/hub/collections/.../linux.yaml
		when the collection is installed, both files are created
	*/
	//non symlinks are local user files or hub files
	if f.Mode()&os.ModeSymlink == 0 {
		local = true
		log.Tracef("%s isn't a symlink", path)
	} else {
		hubpath, err = os.Readlink(path)
		if err != nil {
			return fmt.Errorf("unable to read symlink of %s", path)
		}
		//the symlink target doesn't exist, user might have removed ~/.hub/hub/...yaml without deleting /etc/crowdsec/....yaml
		_, err := os.Lstat(hubpath)
		if os.IsNotExist(err) {
			log.Infof("%s is a symlink to %s that doesn't exist, deleting symlink", path, hubpath)
			//remove the symlink
			if err = os.Remove(path); err != nil {
				return fmt.Errorf("failed to unlink %s: %+v", path, err)
			}
			return nil
		}
		log.Tracef("%s points to %s", path, hubpath)
	}

	//if it's not a symlink and not in hub, it's a local file, don't bother
	if local && !inhub {
		log.Tracef("%s is a local file, skip", path)
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

		hubIdx[ftype][fname] = target
		return nil
	}
	//try to find which configuration item it is
	log.Tracef("check [%s] of %s", fname, ftype)

	match := false
	for k, v := range hubIdx[ftype] {
		log.Tracef("check [%s] vs [%s] : %s", fname, v.RemotePath, ftype+"/"+stage+"/"+fname+".yaml")
		if fname != v.FileName {
			log.Tracef("%s != %s (filename)", fname, v.FileName)
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
			if path == hubdir+"/"+v.RemotePath {
				log.Tracef("marking %s as downloaded", v.Name)
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
		sha, err := getSHA256(path)
		if err != nil {
			log.Fatalf("Failed to get sha of %s : %v", path, err)
		}
		//let's reverse sort the versions to deal with hash collisions (#154)
		versions := make([]string, 0, len(v.Versions))
		for k := range v.Versions {
			versions = append(versions, k)
		}
		sort.Sort(sort.Reverse(sort.StringSlice(versions)))

		for _, version := range versions {
			val := v.Versions[version]
			if sha != val.Digest {
				//log.Printf("matching filenames, wrong hash %s != %s -- %s", sha, val.Digest, spew.Sdump(v))
				continue
			}
			/*we got an exact match, update struct*/
			if !inhub {
				log.Tracef("found exact match for %s, version is %s, latest is %s", v.Name, version, v.Version)
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
				log.Tracef("%s is up-to-date", v.Name)
				v.UpToDate = true
			}
			match = true
			break
		}
		if !match {
			log.Tracef("got tainted match for %s : %s", v.Name, path)
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
		//update the entry if appropriate
		if _, ok := hubIdx[ftype][k]; !ok {
			hubIdx[ftype][k] = v
		} else if !inhub {
			hubIdx[ftype][k] = v
		}
		return nil
	}
	log.Infof("Ignoring file %s of type %s", path, ftype)
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
						return fmt.Errorf("sub collection %s is broken : %s", val.Name, err)
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
	warnings := []string{}

	/*For each, scan PARSERS, PARSERS_OVFLW, SCENARIOS and COLLECTIONS last*/
	for _, scan := range ItemTypes {
		cpath, err := filepath.Abs(fmt.Sprintf("%s/%s", dir, scan))
		if err != nil {
			log.Errorf("failed %s : %s", cpath, err)
		}
		err = filepath.Walk(cpath, parser_visit)
		if err != nil {
			return err, warnings
		}

	}

	for k, v := range hubIdx[COLLECTIONS] {
		if v.Installed {
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
