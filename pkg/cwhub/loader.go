package cwhub

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func validItemFileName(vname string, fauthor string, fname string) bool {
	return (fauthor+"/"+fname == vname+".yaml") || (fauthor+"/"+fname == vname+".yml")
}

type walker struct {
	// the walk/parserVisit function can't receive extra args
	hubdir     string
	installdir string
}

func NewWalker(hub *csconfig.Hub) walker {
	return walker{
		hubdir:     hub.HubDir,
		installdir: hub.ConfigDir,
	}
}

type itemFileInfo struct {
	fname   string
	stage   string
	ftype   string
	fauthor string
}

func (w walker) getItemInfo(path string) (itemFileInfo, bool, error) {
	ret := itemFileInfo{}
	inhub := false

	subs := strings.Split(path, string(os.PathSeparator))

	log.Tracef("path:%s, hubdir:%s, installdir:%s", path, w.hubdir, w.installdir)
	log.Tracef("subs:%v", subs)
	// we're in hub (~/.hub/hub/)
	if strings.HasPrefix(path, w.hubdir) {
		log.Tracef("in hub dir")

		inhub = true
		//.../hub/parsers/s00-raw/crowdsec/skip-pretag.yaml
		//.../hub/scenarios/crowdsec/ssh_bf.yaml
		//.../hub/profiles/crowdsec/linux.yaml
		if len(subs) < 4 {
			log.Fatalf("path is too short : %s (%d)", path, len(subs))
		}

		ret.fname = subs[len(subs)-1]
		ret.fauthor = subs[len(subs)-2]
		ret.stage = subs[len(subs)-3]
		ret.ftype = subs[len(subs)-4]
	} else if strings.HasPrefix(path, w.installdir) { // we're in install /etc/crowdsec/<type>/...
		log.Tracef("in install dir")
		if len(subs) < 3 {
			log.Fatalf("path is too short : %s (%d)", path, len(subs))
		}
		///.../config/parser/stage/file.yaml
		///.../config/postoverflow/stage/file.yaml
		///.../config/scenarios/scenar.yaml
		///.../config/collections/linux.yaml //file is empty
		ret.fname = subs[len(subs)-1]
		ret.stage = subs[len(subs)-2]
		ret.ftype = subs[len(subs)-3]
		ret.fauthor = ""
	} else {
		return itemFileInfo{}, false, fmt.Errorf("file '%s' is not from hub '%s' nor from the configuration directory '%s'", path, w.hubdir, w.installdir)
	}

	log.Tracef("stage:%s ftype:%s", ret.stage, ret.ftype)
	// log.Printf("%s -> name:%s stage:%s", path, fname, stage)

	if ret.stage == SCENARIOS {
		ret.ftype = SCENARIOS
		ret.stage = ""
	} else if ret.stage == COLLECTIONS {
		ret.ftype = COLLECTIONS
		ret.stage = ""
	} else if ret.ftype != PARSERS && ret.ftype != PARSERS_OVFLW {
		// its a PARSER / PARSER_OVFLW with a stage
		return itemFileInfo{}, inhub, fmt.Errorf("unknown configuration type for file '%s'", path)
	}

	log.Tracef("CORRECTED [%s] by [%s] in stage [%s] of type [%s]", ret.fname, ret.fauthor, ret.stage, ret.ftype)

	return ret, inhub, nil
}

func (w walker) parserVisit(path string, f os.DirEntry, err error) error {
	var (
		local   bool
		hubpath string
	)

	if err != nil {
		log.Debugf("while syncing hub dir: %s", err)
		// there is a path error, we ignore the file
		return nil
	}

	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}

	// we only care about files
	if f == nil || f.IsDir() {
		return nil
	}

	// we only care about yaml files
	if !strings.HasSuffix(f.Name(), ".yaml") && !strings.HasSuffix(f.Name(), ".yml") {
		return nil
	}

	info, inhub, err := w.getItemInfo(path)
	if err != nil {
		return err
	}

	/*
		we can encounter 'collections' in the form of a symlink :
		/etc/crowdsec/.../collections/linux.yaml -> ~/.hub/hub/collections/.../linux.yaml
		when the collection is installed, both files are created
	*/
	// non symlinks are local user files or hub files
	if f.Type()&os.ModeSymlink == 0 {
		local = true

		log.Tracef("%s isn't a symlink", path)
	} else {
		hubpath, err = os.Readlink(path)
		if err != nil {
			return fmt.Errorf("unable to read symlink of %s", path)
		}
		// the symlink target doesn't exist, user might have removed ~/.hub/hub/...yaml without deleting /etc/crowdsec/....yaml
		_, err := os.Lstat(hubpath)
		if os.IsNotExist(err) {
			log.Infof("%s is a symlink to %s that doesn't exist, deleting symlink", path, hubpath)
			// remove the symlink
			if err = os.Remove(path); err != nil {
				return fmt.Errorf("failed to unlink %s: %w", path, err)
			}
			return nil
		}
		log.Tracef("%s points to %s", path, hubpath)
	}

	// if it's not a symlink and not in hub, it's a local file, don't bother
	if local && !inhub {
		log.Tracef("%s is a local file, skip", path)
		skippedLocal++
		//	log.Printf("local scenario, skip.")

		_, fileName := filepath.Split(path)

		hubIdx[info.ftype][info.fname] = Item{
			Name:      info.fname,
			Stage:     info.stage,
			Installed: true,
			Type:      info.ftype,
			Local:     true,
			LocalPath: path,
			UpToDate:  true,
			FileName:  fileName,
		}

		return nil
	}

	// try to find which configuration item it is
	log.Tracef("check [%s] of %s", info.fname, info.ftype)

	match := false

	for k, v := range hubIdx[info.ftype] {
		log.Tracef("check [%s] vs [%s] : %s", info.fname, v.RemotePath, info.ftype+"/"+info.stage+"/"+info.fname+".yaml")

		if info.fname != v.FileName {
			log.Tracef("%s != %s (filename)", info.fname, v.FileName)
			continue
		}

		// wrong stage
		if v.Stage != info.stage {
			continue
		}

		// if we are walking hub dir, just mark present files as downloaded
		if inhub {
			// wrong author
			if info.fauthor != v.Author {
				continue
			}

			// wrong file
			if !validItemFileName(v.Name, info.fauthor, info.fname) {
				continue
			}

			if path == w.hubdir+"/"+v.RemotePath {
				log.Tracef("marking %s as downloaded", v.Name)
				v.Downloaded = true
			}
		} else if !hasPathSuffix(hubpath, v.RemotePath) {
			// wrong file
			// <type>/<stage>/<author>/<name>.yaml
			continue
		}

		sha, err := getSHA256(path)
		if err != nil {
			log.Fatalf("Failed to get sha of %s : %v", path, err)
		}

		// let's reverse sort the versions to deal with hash collisions (#154)
		versions := make([]string, 0, len(v.Versions))
		for k := range v.Versions {
			versions = append(versions, k)
		}

		sort.Sort(sort.Reverse(sort.StringSlice(versions)))

		for _, version := range versions {
			val := v.Versions[version]
			if sha != val.Digest {
				// log.Printf("matching filenames, wrong hash %s != %s -- %s", sha, val.Digest, spew.Sdump(v))
				continue
			}

			v.Downloaded = true
			v.LocalHash = sha

			// we got an exact match, update struct
			if !inhub {
				log.Tracef("found exact match for %s, version is %s, latest is %s", v.Name, version, v.Version)
				v.LocalPath = path
				v.LocalVersion = version
				v.Tainted = false
				// if we're walking the hub, present file doesn't means installed file
				v.Installed = true
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

			skippedTainted++
			// the file and the stage is right, but the hash is wrong, it has been tainted by user
			if !inhub {
				v.LocalPath = path
				v.Installed = true
			}

			v.UpToDate = false
			v.LocalVersion = "?"
			v.Tainted = true
			v.LocalHash = sha
		}

		// update the entry if appropriate
		// if _, ok := hubIdx[ftype][k]; !ok || !inhub || v.D {
		// 	fmt.Printf("Updating %s", k)
		// 	hubIdx[ftype][k] = v
		// } else if !inhub {

		// } else if
		hubIdx[info.ftype][k] = v

		return nil
	}

	log.Infof("Ignoring file %s of type %s", path, info.ftype)

	return nil
}

func CollecDepsCheck(v *Item) error {
	if GetVersionStatus(v) != 0 { // not up-to-date
		log.Debugf("%s dependencies not checked : not up-to-date", v.Name)
		return nil
	}

	// if it's a collection, ensure all the items are installed, or tag it as tainted
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
						if val.Tainted {
							v.Tainted = true
						}

						return fmt.Errorf("sub collection %s is broken: %w", val.Name, err)
					}

					hubIdx[ptrtype][p] = val
				}

				// propagate the state of sub-items to set
				if val.Tainted {
					v.Tainted = true
					return fmt.Errorf("tainted %s %s, tainted", ptrtype, p)
				}

				if !val.Installed && v.Installed {
					v.Tainted = true
					return fmt.Errorf("missing %s %s, tainted", ptrtype, p)
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
	warnings := []string{}

	// For each, scan PARSERS, PARSERS_OVFLW, SCENARIOS and COLLECTIONS last
	for _, scan := range ItemTypes {
		cpath, err := filepath.Abs(fmt.Sprintf("%s/%s", dir, scan))
		if err != nil {
			log.Errorf("failed %s : %s", cpath, err)
		}

		err = filepath.WalkDir(cpath, NewWalker(hub).parserVisit)
		if err != nil {
			return err, warnings
		}
	}

	for k, v := range hubIdx[COLLECTIONS] {
		if !v.Installed {
			continue
		}

		versionStatus := GetVersionStatus(&v)
		switch versionStatus {
		case 0: // latest
			if err := CollecDepsCheck(&v); err != nil {
				warnings = append(warnings, fmt.Sprintf("dependency of %s : %s", v.Name, err))
				hubIdx[COLLECTIONS][k] = v
			}
		case 1: // not up-to-date
			warnings = append(warnings, fmt.Sprintf("update for collection %s available (currently:%s, latest:%s)", v.Name, v.LocalVersion, v.Version))
		default: // version is higher than the highest available from hub?
			warnings = append(warnings, fmt.Sprintf("collection %s is in the future (currently:%s, latest:%s)", v.Name, v.LocalVersion, v.Version))
		}

		log.Debugf("installed (%s) - status:%d | installed:%s | latest : %s | full : %+v", v.Name, versionStatus, v.LocalVersion, v.Version, v.Versions)
	}

	return nil, warnings
}

// Updates the infos from HubInit() with the local state
func LocalSync(hub *csconfig.Hub) (error, []string) {
	skippedLocal = 0
	skippedTainted = 0

	err, warnings := SyncDir(hub, hub.ConfigDir)
	if err != nil {
		return fmt.Errorf("failed to scan %s: %w", hub.ConfigDir, err), warnings
	}

	err, _ = SyncDir(hub, hub.HubDir)
	if err != nil {
		return fmt.Errorf("failed to scan %s: %w", hub.HubDir, err), warnings
	}

	return nil, warnings
}

func GetHubIdx(hub *csconfig.Hub) error {
	if hub == nil {
		return fmt.Errorf("no configuration found for hub")
	}

	log.Debugf("loading hub idx %s", hub.HubIndexFile)

	bidx, err := os.ReadFile(hub.HubIndexFile)
	if err != nil {
		return fmt.Errorf("unable to read index file: %w", err)
	}

	ret, err := LoadPkgIndex(bidx)
	if err != nil {
		if !errors.Is(err, ReferenceMissingError) {
			return fmt.Errorf("unable to load existing index: %w", err)
		}

		// XXX: why the error check if we bail out anyway?
		return err
	}

	hubIdx = ret

	err, _ = LocalSync(hub)
	if err != nil {
		return fmt.Errorf("failed to sync Hub index with local deployment : %w", err)
	}

	return nil
}

// LoadPkgIndex loads a local .index.json file and returns the map of parsers/scenarios/collections associated
func LoadPkgIndex(buff []byte) (map[string]map[string]Item, error) {
	var (
		RawIndex     map[string]map[string]Item
		missingItems []string
	)

	if err := json.Unmarshal(buff, &RawIndex); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index: %w", err)
	}

	log.Debugf("%d item types in hub index", len(ItemTypes))

	// Iterate over the different types to complete struct
	for _, itemType := range ItemTypes {
		// complete struct
		log.Tracef("%d item", len(RawIndex[itemType]))

		for idx, item := range RawIndex[itemType] {
			item.Name = idx
			item.Type = itemType
			x := strings.Split(item.RemotePath, "/")
			item.FileName = x[len(x)-1]
			RawIndex[itemType][idx] = item

			if itemType != COLLECTIONS {
				continue
			}

			// if it's a collection, check its sub-items are present
			// XXX should be done later
			for idx, ptr := range [][]string{item.Parsers, item.PostOverflows, item.Scenarios, item.Collections} {
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

	if len(missingItems) > 0 {
		return RawIndex, fmt.Errorf("%q: %w", missingItems, ReferenceMissingError)
	}

	return RawIndex, nil
}
