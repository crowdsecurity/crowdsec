package cwhub

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"slices"
)

func isYAMLFileName(path string) bool {
	return strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")
}

func handleSymlink(path string) (string, error) {
	hubpath, err := os.Readlink(path)
	if err != nil {
		return "", fmt.Errorf("unable to read symlink of %s", path)
	}
	// the symlink target doesn't exist, user might have removed ~/.hub/hub/...yaml without deleting /etc/crowdsec/....yaml
	_, err = os.Lstat(hubpath)
	if os.IsNotExist(err) {
		log.Infof("%s is a symlink to %s that doesn't exist, deleting symlink", path, hubpath)
		// remove the symlink
		if err = os.Remove(path); err != nil {
			return "", fmt.Errorf("failed to unlink %s: %w", path, err)
		}

		// XXX: is this correct?
		return "", nil
	}

	return hubpath, nil
}

func getSHA256(filepath string) (string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("unable to open '%s': %w", filepath, err)
	}

	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("unable to calculate sha256 of '%s': %w", filepath, err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

type itemFileInfo struct {
	fname   string
	stage   string
	ftype   string
	fauthor string
}

func (h *Hub) getItemInfo(path string) (itemFileInfo, bool, error) {
	ret := itemFileInfo{}
	inhub := false

	hubDir := h.local.HubDir
	installDir := h.local.InstallDir

	subs := strings.Split(path, string(os.PathSeparator))

	log.Tracef("path:%s, hubdir:%s, installdir:%s", path, hubDir, installDir)
	log.Tracef("subs:%v", subs)
	// we're in hub (~/.hub/hub/)
	if strings.HasPrefix(path, hubDir) {
		log.Tracef("in hub dir")

		inhub = true
		//.../hub/parsers/s00-raw/crowdsec/skip-pretag.yaml
		//.../hub/scenarios/crowdsec/ssh_bf.yaml
		//.../hub/profiles/crowdsec/linux.yaml
		if len(subs) < 4 {
			return itemFileInfo{}, false, fmt.Errorf("path is too short: %s (%d)", path, len(subs))
		}

		ret.fname = subs[len(subs)-1]
		ret.fauthor = subs[len(subs)-2]
		ret.stage = subs[len(subs)-3]
		ret.ftype = subs[len(subs)-4]
	} else if strings.HasPrefix(path, installDir) { // we're in install /etc/crowdsec/<type>/...
		log.Tracef("in install dir")
		if len(subs) < 3 {
			return itemFileInfo{}, false, fmt.Errorf("path is too short: %s (%d)", path, len(subs))
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
		return itemFileInfo{}, false, fmt.Errorf("file '%s' is not from hub '%s' nor from the configuration directory '%s'", path, hubDir, installDir)
	}

	log.Tracef("stage:%s ftype:%s", ret.stage, ret.ftype)
	// log.Infof("%s -> name:%s stage:%s", path, fname, stage)

	if ret.stage == SCENARIOS {
		ret.ftype = SCENARIOS
		ret.stage = ""
	} else if ret.stage == COLLECTIONS {
		ret.ftype = COLLECTIONS
		ret.stage = ""
	} else if ret.ftype != PARSERS && ret.ftype != POSTOVERFLOWS {
		// it's a PARSER / POSTOVERFLOW with a stage
		return itemFileInfo{}, inhub, fmt.Errorf("unknown configuration type for file '%s'", path)
	}

	log.Tracef("CORRECTED [%s] by [%s] in stage [%s] of type [%s]", ret.fname, ret.fauthor, ret.stage, ret.ftype)

	return ret, inhub, nil
}

func (h *Hub) itemVisit(path string, f os.DirEntry, err error) error {
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

	if !isYAMLFileName(f.Name()) {
		return nil
	}

	info, inhub, err := h.getItemInfo(path)
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
		hubpath, err = handleSymlink(path)
		if err != nil {
			return err
		}
		log.Tracef("%s points to %s", path, hubpath)

		if hubpath == "" {
			// XXX: is this correct?
			return nil
		}
	}

	// if it's not a symlink and not in hub, it's a local file, don't bother
	if local && !inhub {
		log.Tracef("%s is a local file, skip", path)
		h.skippedLocal++
		//	log.Infof("local scenario, skip.")

		_, fileName := filepath.Split(path)

		h.Items[info.ftype][info.fname] = Item{
			Name:      info.fname,
			Stage:     info.stage,
			Installed: true,
			Type:      info.ftype,
			LocalPath: path,
			UpToDate:  true,
			FileName:  fileName,
		}

		return nil
	}

	// try to find which configuration item it is
	log.Tracef("check [%s] of %s", info.fname, info.ftype)

	match := false

	for name, item := range h.Items[info.ftype] {
		log.Tracef("check [%s] vs [%s]: %s", info.fname, item.RemotePath, info.ftype+"/"+info.stage+"/"+info.fname+".yaml")

		if info.fname != item.FileName {
			log.Tracef("%s != %s (filename)", info.fname, item.FileName)
			continue
		}

		// wrong stage
		if item.Stage != info.stage {
			continue
		}

		// if we are walking hub dir, just mark present files as downloaded
		if inhub {
			// wrong author
			if info.fauthor != item.Author {
				continue
			}

			// not the item we're looking for
			if !item.validPath(info.fauthor, info.fname) {
				continue
			}

			if path == h.local.HubDir+"/"+item.RemotePath {
				log.Tracef("marking %s as downloaded", item.Name)
				item.Downloaded = true
			}
		} else if !hasPathSuffix(hubpath, item.RemotePath) {
			// wrong file
			// <type>/<stage>/<author>/<name>.yaml
			continue
		}

		sha, err := getSHA256(path)
		if err != nil {
			log.Fatalf("Failed to get sha of %s: %v", path, err)
		}

		// let's reverse sort the versions to deal with hash collisions (#154)
		// XXX: we sure, lexical sorting?
		versions := make([]string, 0, len(item.Versions))
		for k := range item.Versions {
			versions = append(versions, k)
		}

		sort.Sort(sort.Reverse(sort.StringSlice(versions)))

		for _, version := range versions {
			if item.Versions[version].Digest != sha {
				// log.Infof("matching filenames, wrong hash %s != %s -- %s", sha, val.Digest, spew.Sdump(v))
				continue
			}

			// we got an exact match, update struct

			item.Downloaded = true
			item.LocalHash = sha

			if !inhub {
				log.Tracef("found exact match for %s, version is %s, latest is %s", item.Name, version, item.Version)
				item.LocalPath = path
				item.LocalVersion = version
				item.Tainted = false
				// if we're walking the hub, present file doesn't means installed file
				item.Installed = true
			}

			if version == item.Version {
				log.Tracef("%s is up-to-date", item.Name)
				item.UpToDate = true
			}

			match = true

			break
		}

		if !match {
			log.Tracef("got tainted match for %s: %s", item.Name, path)

			h.skippedTainted++

			// the file and the stage is right, but the hash is wrong, it has been tainted by user
			if !inhub {
				item.LocalPath = path
				item.Installed = true
			}

			item.UpToDate = false
			item.LocalVersion = "?"
			item.Tainted = true
			item.LocalHash = sha
		}

		h.Items[info.ftype][name] = item

		return nil
	}

	log.Infof("Ignoring file %s of type %s", path, info.ftype)

	return nil
}

func (h *Hub) CollectDepsCheck(v *Item) error {
	if v.Type != COLLECTIONS {
		return nil
	}

	if v.versionStatus() != 0 { // not up-to-date
		log.Debugf("%s dependencies not checked: not up-to-date", v.Name)
		return nil
	}

	// if it's a collection, ensure all the items are installed, or tag it as tainted
	log.Tracef("checking submembers of %s installed:%t", v.Name, v.Installed)

	for _, sub := range v.SubItems() {
		subItem, ok := h.Items[sub.Type][sub.Name]
		if !ok {
			return fmt.Errorf("referred %s %s in collection %s doesn't exist", sub.Type, sub.Name, v.Name)
		}

		log.Tracef("check %s installed:%t", subItem.Name, subItem.Installed)

		if !v.Installed {
			continue
		}

		if subItem.Type == COLLECTIONS {
			log.Tracef("collec, recurse.")

			if err := h.CollectDepsCheck(&subItem); err != nil {
				if subItem.Tainted {
					v.Tainted = true
				}

				return fmt.Errorf("sub collection %s is broken: %w", subItem.Name, err)
			}

			h.Items[sub.Type][sub.Name] = subItem
		}

		// propagate the state of sub-items to set
		if subItem.Tainted {
			v.Tainted = true
			return fmt.Errorf("tainted %s %s, tainted", sub.Type, sub.Name)
		}

		if !subItem.Installed && v.Installed {
			v.Tainted = true
			return fmt.Errorf("missing %s %s, tainted", sub.Type, sub.Name)
		}

		if !subItem.UpToDate {
			v.UpToDate = false
			return fmt.Errorf("outdated %s %s", sub.Type, sub.Name)
		}

		if !slices.Contains(subItem.BelongsToCollections, v.Name) {
			subItem.BelongsToCollections = append(subItem.BelongsToCollections, v.Name)
		}

		h.Items[sub.Type][sub.Name] = subItem

		log.Tracef("checking for %s - tainted:%t uptodate:%t", sub.Name, v.Tainted, v.UpToDate)
	}

	return nil
}

func (h *Hub) SyncDir(dir string) ([]string, error) {
	warnings := []string{}

	// For each, scan PARSERS, POSTOVERFLOWS, SCENARIOS and COLLECTIONS last
	for _, scan := range ItemTypes {
		cpath, err := filepath.Abs(fmt.Sprintf("%s/%s", dir, scan))
		if err != nil {
			log.Errorf("failed %s: %s", cpath, err)
		}

		// explicit check for non existing directory, avoid spamming log.Debug
		if _, err = os.Stat(cpath); os.IsNotExist(err) {
			log.Tracef("directory %s doesn't exist, skipping", cpath)
			continue
		}

		if err = filepath.WalkDir(cpath, h.itemVisit); err != nil {
			return warnings, err
		}
	}

	for name, item := range h.Items[COLLECTIONS] {
		if !item.Installed {
			continue
		}

		vs := item.versionStatus()
		switch vs {
		case 0: // latest
			if err := h.CollectDepsCheck(&item); err != nil {
				warnings = append(warnings, fmt.Sprintf("dependency of %s: %s", item.Name, err))
				h.Items[COLLECTIONS][name] = item
			}
		case 1: // not up-to-date
			warnings = append(warnings, fmt.Sprintf("update for collection %s available (currently:%s, latest:%s)", item.Name, item.LocalVersion, item.Version))
		default: // version is higher than the highest available from hub?
			warnings = append(warnings, fmt.Sprintf("collection %s is in the future (currently:%s, latest:%s)", item.Name, item.LocalVersion, item.Version))
		}

		log.Debugf("installed (%s) - status: %d | installed: %s | latest: %s | full: %+v", item.Name, vs, item.LocalVersion, item.Version, item.Versions)
	}

	return warnings, nil
}

// Updates the info from HubInit() with the local state
func (h *Hub) LocalSync() ([]string, error) {
	h.skippedLocal = 0
	h.skippedTainted = 0

	warnings, err := h.SyncDir(h.local.InstallDir)
	if err != nil {
		return warnings, fmt.Errorf("failed to scan %s: %w", h.local.InstallDir, err)
	}

	if _, err = h.SyncDir(h.local.HubDir); err != nil {
		return warnings, fmt.Errorf("failed to scan %s: %w", h.local.HubDir, err)
	}

	return warnings, nil
}
