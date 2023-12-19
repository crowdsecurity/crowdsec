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
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"slices"
)

func isYAMLFileName(path string) bool {
	return strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")
}

// linkTarget returns the target of a symlink, or empty string if it's dangling.
func linkTarget(path string, logger *logrus.Logger) (string, error) {
	hubpath, err := os.Readlink(path)
	if err != nil {
		return "", fmt.Errorf("unable to read symlink: %s", path)
	}

	logger.Tracef("symlink %s -> %s", path, hubpath)

	_, err = os.Lstat(hubpath)
	if os.IsNotExist(err) {
		logger.Warningf("link target does not exist: %s -> %s", path, hubpath)
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

// information used to create a new Item, from a file path.
type itemFileInfo struct {
	inhub   bool
	fname   string
	stage   string
	ftype   string
	fauthor string
}

func (h *Hub) getItemFileInfo(path string, logger *logrus.Logger) (*itemFileInfo, error) {
	var ret *itemFileInfo

	hubDir := h.local.HubDir
	installDir := h.local.InstallDir

	subs := strings.Split(path, string(os.PathSeparator))

	logger.Tracef("path:%s, hubdir:%s, installdir:%s", path, hubDir, installDir)
	logger.Tracef("subs:%v", subs)
	// we're in hub (~/.hub/hub/)
	if strings.HasPrefix(path, hubDir) {
		logger.Tracef("in hub dir")

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
		logger.Tracef("in install dir")
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

	logger.Tracef("stage:%s ftype:%s", ret.stage, ret.ftype)

	if ret.ftype != PARSERS && ret.ftype != POSTOVERFLOWS {
		if !slices.Contains(ItemTypes, ret.stage) {
			return nil, fmt.Errorf("unknown configuration type for file '%s'", path)
		}

		ret.ftype = ret.stage
		ret.stage = ""
	}

	logger.Tracef("CORRECTED [%s] by [%s] in stage [%s] of type [%s]", ret.fname, ret.fauthor, ret.stage, ret.ftype)

	return ret, nil
}

// sortedVersions returns the input data, sorted in reverse order (new, old) by semver.
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

func newLocalItem(h *Hub, path string, info *itemFileInfo) (*Item, error) {
	type localItemName struct {
		Name string `yaml:"name"`
	}

	_, fileName := filepath.Split(path)

	item := &Item{
		hub:      h,
		Name:     info.fname,
		Stage:    info.stage,
		Type:     info.ftype,
		FileName: fileName,
		State: ItemState{
			LocalPath: path,
			Installed: true,
			UpToDate:  true,
		},
	}

	// try to read the name from the file
	itemName := localItemName{}

	itemContent, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	err = yaml.Unmarshal(itemContent, &itemName)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", path, err)
	}

	if itemName.Name != "" {
		item.Name = itemName.Name
	}

	return item, nil
}

func (h *Hub) itemVisit(path string, f os.DirEntry, err error) error {
	hubpath := ""

	if err != nil {
		h.logger.Debugf("while syncing hub dir: %s", err)
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

	info, err := h.getItemFileInfo(path, h.logger)
	if err != nil {
		return err
	}

	// non symlinks are local user files or hub files
	if f.Type()&os.ModeSymlink == 0 {
		h.logger.Tracef("%s is not a symlink", path)

		if !info.inhub {
			h.logger.Tracef("%s is a local file, skip", path)

			item, err := newLocalItem(h, path, info)
			if err != nil {
				return err
			}

			h.addItem(item)

			return nil
		}
	} else {
		hubpath, err = linkTarget(path, h.logger)
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
	h.logger.Tracef("check [%s] of %s", info.fname, info.ftype)

	for _, item := range h.GetItemMap(info.ftype) {
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
				h.logger.Tracef("marking %s as downloaded", item.Name)
				item.State.Downloaded = true
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

		return nil
	}

	h.logger.Infof("Ignoring file %s of type %s", path, info.ftype)

	return nil
}

// checkSubItemVersions checks for the presence, taint and version state of sub-items.
func (i *Item) checkSubItemVersions() []string {
	warn := make([]string, 0)

	if !i.HasSubItems() {
		return warn
	}

	if i.versionStatus() != versionUpToDate {
		i.hub.logger.Debugf("%s dependencies not checked: not up-to-date", i.Name)
		return warn
	}

	// ensure all the sub-items are installed, or tag the parent as tainted
	i.hub.logger.Tracef("checking submembers of %s installed:%t", i.Name, i.State.Installed)

	for _, sub := range i.SubItems() {
		i.hub.logger.Tracef("check %s installed:%t", sub.Name, sub.State.Installed)

		if !i.State.Installed {
			continue
		}

		if w := sub.checkSubItemVersions(); len(w) > 0 {
			if sub.State.Tainted {
				i.addTaint(sub)
				warn = append(warn, fmt.Sprintf("%s is tainted by %s", i.Name, sub.FQName()))
			}

			warn = append(warn, w...)

			continue
		}

		if sub.State.Tainted {
			i.addTaint(sub)
			warn = append(warn, fmt.Sprintf("%s is tainted by %s", i.Name, sub.FQName()))

			continue
		}

		if !sub.State.Installed && i.State.Installed {
			i.addTaint(sub)
			warn = append(warn, fmt.Sprintf("%s is tainted by missing %s", i.Name, sub.FQName()))

			continue
		}

		if !sub.State.UpToDate {
			i.State.UpToDate = false
			warn = append(warn, fmt.Sprintf("%s is tainted by outdated %s", i.Name, sub.FQName()))

			continue
		}

		i.hub.logger.Tracef("checking for %s - tainted:%t uptodate:%t", sub.Name, i.State.Tainted, i.State.UpToDate)
	}

	return warn
}

// syncDir scans a directory for items, and updates the Hub state accordingly.
func (h *Hub) syncDir(dir string) error {
	// For each, scan PARSERS, POSTOVERFLOWS... and COLLECTIONS last
	for _, scan := range ItemTypes {
		// cpath: top-level item directory, either downloaded or installed items.
		// i.e. /etc/crowdsec/parsers, /etc/crowdsec/hub/parsers, ...
		cpath, err := filepath.Abs(fmt.Sprintf("%s/%s", dir, scan))
		if err != nil {
			h.logger.Errorf("failed %s: %s", cpath, err)
			continue
		}

		// explicit check for non existing directory, avoid spamming log.Debug
		if _, err = os.Stat(cpath); os.IsNotExist(err) {
			h.logger.Tracef("directory %s doesn't exist, skipping", cpath)
			continue
		}

		if err = filepath.WalkDir(cpath, h.itemVisit); err != nil {
			return err
		}
	}

	return nil
}

// insert a string in a sorted slice, case insensitive, and return the new slice.
func insertInOrderNoCase(sl []string, value string) []string {
	i := sort.Search(len(sl), func(i int) bool {
		return strings.ToLower(sl[i]) >= strings.ToLower(value)
	})

	return append(sl[:i], append([]string{value}, sl[i:]...)...)
}

func removeDuplicates(sl []string) []string {
	seen := make(map[string]struct{}, len(sl))
	j := 0

	for _, v := range sl {
		if _, ok := seen[v]; ok {
			continue
		}

		seen[v] = struct{}{}
		sl[j] = v
		j++
	}

	return sl[:j]
}

// localSync updates the hub state with downloaded, installed and local items.
func (h *Hub) localSync() error {
	err := h.syncDir(h.local.InstallDir)
	if err != nil {
		return fmt.Errorf("failed to scan %s: %w", h.local.InstallDir, err)
	}

	if err = h.syncDir(h.local.HubDir); err != nil {
		return fmt.Errorf("failed to scan %s: %w", h.local.HubDir, err)
	}

	warnings := make([]string, 0)

	for _, item := range h.GetItemMap(COLLECTIONS) {
		// check for cyclic dependencies
		subs, err := item.descendants()
		if err != nil {
			return err
		}

		// populate the sub- and sub-sub-items with the collections they belong to
		for _, sub := range subs {
			sub.State.BelongsToCollections = insertInOrderNoCase(sub.State.BelongsToCollections, item.Name)
		}

		if !item.State.Installed {
			continue
		}

		vs := item.versionStatus()
		switch vs {
		case versionUpToDate: // latest
			if w := item.checkSubItemVersions(); len(w) > 0 {
				warnings = append(warnings, w...)
			}
		case versionUpdateAvailable: // not up-to-date
			warnings = append(warnings, fmt.Sprintf("update for collection %s available (currently:%s, latest:%s)", item.Name, item.State.LocalVersion, item.Version))
		case versionFuture:
			warnings = append(warnings, fmt.Sprintf("collection %s is in the future (currently:%s, latest:%s)", item.Name, item.State.LocalVersion, item.Version))
		case versionUnknown:
			if !item.State.IsLocal() {
				warnings = append(warnings, fmt.Sprintf("collection %s is tainted by local changes (latest:%s)", item.Name, item.Version))
			}
		}

		h.logger.Debugf("installed (%s) - status: %d | installed: %s | latest: %s | full: %+v", item.Name, vs, item.State.LocalVersion, item.Version, item.Versions)
	}

	h.Warnings = removeDuplicates(warnings)

	return nil
}

func (i *Item) setVersionState(path string, inhub bool) error {
	var err error

	i.State.LocalHash, err = getSHA256(path)
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

	i.State.LocalVersion = "?"

	for _, version := range versions {
		if i.Versions[version].Digest == i.State.LocalHash {
			i.State.LocalVersion = version
			break
		}
	}

	if i.State.LocalVersion == "?" {
		i.hub.logger.Tracef("got tainted match for %s: %s", i.Name, path)

		if !inhub {
			i.State.LocalPath = path
			i.State.Installed = true
		}

		i.State.UpToDate = false
		i.addTaint(i)

		return nil
	}

	// we got an exact match, update struct

	i.State.Downloaded = true

	if !inhub {
		i.hub.logger.Tracef("found exact match for %s, version is %s, latest is %s", i.Name, i.State.LocalVersion, i.Version)
		i.State.LocalPath = path
		i.State.Tainted = false
		// if we're walking the hub, present file doesn't means installed file
		i.State.Installed = true
	}

	if i.State.LocalVersion == i.Version {
		i.hub.logger.Tracef("%s is up-to-date", i.Name)
		i.State.UpToDate = true
	}

	return nil
}
