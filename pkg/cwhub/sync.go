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

	"github.com/Masterminds/semver/v3"
	log "github.com/sirupsen/logrus"
	"slices"
)

func isYAMLFileName(path string) bool {
	return strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")
}

// linkTarget returns the target of a symlink, or empty string if it's dangling
func linkTarget(path string) (string, error) {
	hubpath, err := os.Readlink(path)
	if err != nil {
		return "", fmt.Errorf("unable to read symlink: %s", path)
	}

	log.Tracef("symlink %s -> %s", path, hubpath)

	_, err = os.Lstat(hubpath)
	if os.IsNotExist(err) {
		log.Infof("link target does not exist: %s -> %s", path, hubpath)
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
	inhub   bool
	fname   string
	stage   string
	ftype   string
	fauthor string
}

func (h *Hub) getItemFileInfo(path string) (*itemFileInfo, error) {
	var ret *itemFileInfo

	hubDir := h.local.HubDir
	installDir := h.local.InstallDir

	subs := strings.Split(path, string(os.PathSeparator))

	log.Tracef("path:%s, hubdir:%s, installdir:%s", path, hubDir, installDir)
	log.Tracef("subs:%v", subs)
	// we're in hub (~/.hub/hub/)
	if strings.HasPrefix(path, hubDir) {
		log.Tracef("in hub dir")

		//.../hub/parsers/s00-raw/crowdsec/skip-pretag.yaml
		//.../hub/scenarios/crowdsec/ssh_bf.yaml
		//.../hub/profiles/crowdsec/linux.yaml
		if len(subs) < 4 {
			return nil, fmt.Errorf("path is too short: %s (%d)", path, len(subs))
		}

		ret = &itemFileInfo{
			inhub:   true,
			fname:   subs[len(subs)-1],
			fauthor: subs[len(subs)-2],
			stage:   subs[len(subs)-3],
			ftype:   subs[len(subs)-4],
		}
	} else if strings.HasPrefix(path, installDir) { // we're in install /etc/crowdsec/<type>/...
		log.Tracef("in install dir")
		if len(subs) < 3 {
			return nil, fmt.Errorf("path is too short: %s (%d)", path, len(subs))
		}
		///.../config/parser/stage/file.yaml
		///.../config/postoverflow/stage/file.yaml
		///.../config/scenarios/scenar.yaml
		///.../config/collections/linux.yaml //file is empty
		ret = &itemFileInfo{
			inhub:   false,
			fname:   subs[len(subs)-1],
			stage:   subs[len(subs)-2],
			ftype:   subs[len(subs)-3],
			fauthor: "",
		}
	} else {
		return nil, fmt.Errorf("file '%s' is not from hub '%s' nor from the configuration directory '%s'", path, hubDir, installDir)
	}

	log.Tracef("stage:%s ftype:%s", ret.stage, ret.ftype)

	if ret.stage == SCENARIOS {
		ret.ftype = SCENARIOS
		ret.stage = ""
	} else if ret.stage == COLLECTIONS {
		ret.ftype = COLLECTIONS
		ret.stage = ""
	} else if ret.ftype != PARSERS && ret.ftype != POSTOVERFLOWS {
		// it's a PARSER / POSTOVERFLOW with a stage
		return nil, fmt.Errorf("unknown configuration type for file '%s'", path)
	}

	log.Tracef("CORRECTED [%s] by [%s] in stage [%s] of type [%s]", ret.fname, ret.fauthor, ret.stage, ret.ftype)

	return ret, nil
}

// sortedVersions returns the input data, sorted in reverse order (new, old) by semver
func sortedVersions(raw []string) ([]string, error) {
	vs := make([]*semver.Version, len(raw))

	for idx, r := range raw {
		v, err := semver.NewVersion(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r, err)
		}

		vs[idx] = v
	}

	sort.Sort(sort.Reverse(semver.Collection(vs)))

	ret := make([]string, len(vs))
	for idx, v := range vs {
		ret[idx] = v.Original()
	}

	return ret, nil
}

func newLocalItem(h *Hub, path string, info *itemFileInfo) *Item {
	_, fileName := filepath.Split(path)

	return &Item{
		hub:       h,
		Name:      info.fname,
		Stage:     info.stage,
		Installed: true,
		Type:      info.ftype,
		LocalPath: path,
		UpToDate:  true,
		FileName:  fileName,
	}
}

func (h *Hub) itemVisit(path string, f os.DirEntry, err error) error {
	hubpath := ""

	if err != nil {
		log.Debugf("while syncing hub dir: %s", err)
		// there is a path error, we ignore the file
		return nil
	}

	// only happens if the current working directory was removed (!)
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}

	// we only care about YAML files
	if f == nil || f.IsDir() || !isYAMLFileName(f.Name()) {
		return nil
	}

	info, err := h.getItemFileInfo(path)
	if err != nil {
		return err
	}

	// non symlinks are local user files or hub files
	if f.Type()&os.ModeSymlink == 0 {
		log.Tracef("%s is not a symlink", path)

		if !info.inhub {
			log.Tracef("%s is a local file, skip", path)
			h.Items[info.ftype][info.fname] = newLocalItem(h, path, info)

			return nil
		}
	} else {
		hubpath, err = linkTarget(path)
		if err != nil {
			return err
		}

		if hubpath == "" {
			// target does not exist, the user might have removed the file
			// or switched to a hub branch without it
			return nil
		}
	}

	// try to find which configuration item it is
	log.Tracef("check [%s] of %s", info.fname, info.ftype)

	for name, item := range h.Items[info.ftype] {
		if info.fname != item.FileName {
			continue
		}

		if item.Stage != info.stage {
			continue
		}

		// if we are walking hub dir, just mark present files as downloaded
		if info.inhub {
			// wrong author
			if info.fauthor != item.Author {
				continue
			}

			// not the item we're looking for
			if !item.validPath(info.fauthor, info.fname) {
				continue
			}

			src, err := item.downloadPath()
			if err != nil {
				return err
			}

			if path == src {
				log.Tracef("marking %s as downloaded", item.Name)
				item.Downloaded = true
			}
		} else if !hasPathSuffix(hubpath, item.RemotePath) {
			// wrong file
			// <type>/<stage>/<author>/<name>.yaml
			continue
		}

		err := item.setVersionState(path, info.inhub)
		if err != nil {
			return err
		}

		h.Items[info.ftype][name] = item

		return nil
	}

	log.Infof("Ignoring file %s of type %s", path, info.ftype)

	return nil
}

// checkSubItems checks for the presence, taint and version state of sub-items
func (h *Hub) checkSubItems(v *Item) error {
	if !v.HasSubItems() {
		return nil
	}

	if v.versionStatus() != VersionUpToDate {
		log.Debugf("%s dependencies not checked: not up-to-date", v.Name)
		return nil
	}

	// ensure all the sub-items are installed, or tag the parent as tainted
	log.Tracef("checking submembers of %s installed:%t", v.Name, v.Installed)

	for _, sub := range v.SubItems() {
		log.Tracef("check %s installed:%t", sub.Name, sub.Installed)

		if !v.Installed {
			continue
		}

		if err := h.checkSubItems(sub); err != nil {
			if sub.Tainted {
				v.Tainted = true
			}

			return fmt.Errorf("sub collection %s is broken: %w", sub.Name, err)
		}

		if sub.Tainted {
			v.Tainted = true
			// XXX: improve msg
			return fmt.Errorf("tainted %s %s, tainted", sub.Type, sub.Name)
		}

		if !sub.Installed && v.Installed {
			v.Tainted = true
			// XXX: improve msg
			return fmt.Errorf("missing %s %s, tainted", sub.Type, sub.Name)
		}

		if !sub.UpToDate {
			v.UpToDate = false
			return fmt.Errorf("outdated %s %s", sub.Type, sub.Name)
		}

		if !slices.Contains(sub.BelongsToCollections, v.Name) {
			sub.BelongsToCollections = append(sub.BelongsToCollections, v.Name)
		}

		log.Tracef("checking for %s - tainted:%t uptodate:%t", sub.Name, v.Tainted, v.UpToDate)
	}

	return nil
}

// syncDir scans a directory for items, and updates the Hub state accordingly
func (h *Hub) syncDir(dir string) error {
	// For each, scan PARSERS, POSTOVERFLOWS, SCENARIOS and COLLECTIONS last
	for _, scan := range ItemTypes {
		// cpath: top-level item directory, either downloaded or installed items.
		// i.e. /etc/crowdsec/parsers, /etc/crowdsec/hub/parsers, ...
		cpath, err := filepath.Abs(fmt.Sprintf("%s/%s", dir, scan))
		if err != nil {
			log.Errorf("failed %s: %s", cpath, err)
			continue
		}

		// explicit check for non existing directory, avoid spamming log.Debug
		if _, err = os.Stat(cpath); os.IsNotExist(err) {
			log.Tracef("directory %s doesn't exist, skipping", cpath)
			continue
		}

		if err = filepath.WalkDir(cpath, h.itemVisit); err != nil {
			return err
		}
	}

	return nil
}

// localSync updates the hub state with downloaded, installed and local items
func (h *Hub) localSync() error {
	err := h.syncDir(h.local.InstallDir)
	if err != nil {
		return fmt.Errorf("failed to scan %s: %w", h.local.InstallDir, err)
	}

	if err = h.syncDir(h.local.HubDir); err != nil {
		return fmt.Errorf("failed to scan %s: %w", h.local.HubDir, err)
	}

	warnings := make([]string, 0)

	for _, item := range h.Items[COLLECTIONS] {
		if _, err := item.allDependencies(); err != nil {
			return err
		}

		if !item.Installed {
			continue
		}

		vs := item.versionStatus()
		switch vs {
		case VersionUpToDate: // latest
			if err := h.checkSubItems(item); err != nil {
				warnings = append(warnings, fmt.Sprintf("dependency of %s: %s", item.Name, err))
			}
		case VersionUpdateAvailable: // not up-to-date
			warnings = append(warnings, fmt.Sprintf("update for collection %s available (currently:%s, latest:%s)", item.Name, item.LocalVersion, item.Version))
		case VersionFuture:
			warnings = append(warnings, fmt.Sprintf("collection %s is in the future (currently:%s, latest:%s)", item.Name, item.LocalVersion, item.Version))
		case VersionUnknown:
			warnings = append(warnings, fmt.Sprintf("collection %s is tainted (latest:%s)", item.Name, item.Version))
		}

		log.Debugf("installed (%s) - status: %d | installed: %s | latest: %s | full: %+v", item.Name, vs, item.LocalVersion, item.Version, item.Versions)
	}

	h.Warnings = warnings

	return nil
}

func (i *Item) setVersionState(path string, inhub bool) error {
	var err error

	i.LocalHash, err = getSHA256(path)
	if err != nil {
		return fmt.Errorf("failed to get sha256 of %s: %w", path, err)
	}

	// let's reverse sort the versions to deal with hash collisions (#154)
	versions := make([]string, 0, len(i.Versions))
	for k := range i.Versions {
		versions = append(versions, k)
	}

	versions, err = sortedVersions(versions)
	if err != nil {
		return fmt.Errorf("while syncing %s %s: %w", i.Type, i.FileName, err)
	}

	i.LocalVersion = "?"

	for _, version := range versions {
		if i.Versions[version].Digest == i.LocalHash {
			i.LocalVersion = version
			break
		}
	}

	if i.LocalVersion == "?" {
		log.Tracef("got tainted match for %s: %s", i.Name, path)

		if !inhub {
			i.LocalPath = path
			i.Installed = true
		}

		i.UpToDate = false
		i.Tainted = true

		return nil
	}

	// we got an exact match, update struct

	i.Downloaded = true

	if !inhub {
		log.Tracef("found exact match for %s, version is %s, latest is %s", i.Name, i.LocalVersion, i.Version)
		i.LocalPath = path
		i.Tainted = false
		// if we're walking the hub, present file doesn't means installed file
		i.Installed = true
	}

	if i.LocalVersion == i.Version {
		log.Tracef("%s is up-to-date", i.Name)
		i.UpToDate = true
	}

	return nil
}
