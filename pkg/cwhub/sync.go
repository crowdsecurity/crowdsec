package cwhub

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/downloader"
)

func isYAMLFileName(path string) bool {
	return strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")
}

// resolveSymlink returns the ultimate target path of a symlink
// returns error if the symlink is dangling or too many symlinks are followed
func resolveSymlink(path string) (string, error) {
	const maxSymlinks = 10 // Prevent infinite loops
	for range maxSymlinks {
		fi, err := os.Lstat(path)
		if err != nil {
			return "", err // dangling link
		}

		if fi.Mode()&os.ModeSymlink == 0 {
			// found the target
			return path, nil
		}

		path, err = os.Readlink(path)
		if err != nil {
			return "", err
		}

		// relative to the link's directory?
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(path), path)
		}
	}

	return "", errors.New("too many levels of symbolic links")
}

// isPathInside checks if a path is inside the given directory
func isPathInside(path, dir string) (bool, error) {
	absFile, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}

	rel, err := filepath.Rel(absDir, absFile)
	if err != nil {
		return false, err
	}

	return !strings.HasPrefix(rel, ".."), nil
}

// itemSpec contains some information needed to complete the items
// after they have been parsed from the index. itemSpecs are created by
// scanning the hub (/etc/crowdsec/hub/*) and install (/etc/crowdsec/*) directories.
// Only directories for the known types are scanned.
type itemSpec struct {
	path  string // full path to the file (or link)
	fname string // name of the item:
	// for local item, taken from the file content or defaults to the filename (including extension)
	// for non-local items, always {author}/{name}
	stage   string // stage for parsers and overflows
	ftype   string // type, plural (collections, contexts etc.)
	fauthor string // author - empty for local items
	inhub   bool   // true if the spec comes from the hub dir
	target  string // the target of path if it's a link, otherwise == path
	local   bool   // is this a spec for a local item?
}

func newHubItemSpec(path string, subs []string) (*itemSpec, error) {
	// .../hub/parsers/s00-raw/crowdsecurity/skip-pretag.yaml
	// .../hub/scenarios/crowdsecurity/ssh_bf.yaml
	// .../hub/profiles/crowdsecurity/linux.yaml
	if len(subs) < 3 {
		return nil, fmt.Errorf("path is too short: %s (%d)", path, len(subs))
	}

	ftype := subs[0]
	if !slices.Contains(ItemTypes, ftype) {
		// this doesn't really happen anymore, because we only scan the {hubtype} directories
		return nil, fmt.Errorf("unknown configuration type '%s'", ftype)
	}

	stage := ""
	fauthor := subs[1]
	fname := subs[2]

	if ftype == PARSERS || ftype == POSTOVERFLOWS {
		if len(subs) < 4 {
			return nil, fmt.Errorf("path is too short: %s (%d)", path, len(subs))
		}

		stage = subs[1]
		fauthor = subs[2]
		fname = subs[3]
	}

	spec := itemSpec{
		path:    path,
		inhub:   true,
		ftype:   ftype,
		stage:   stage,
		fauthor: fauthor,
		fname:   fname,
	}

	return &spec, nil
}

func newInstallItemSpec(path string, subs []string) (*itemSpec, error) {
	// .../config/parser/stage/file.yaml
	// .../config/postoverflow/stage/file.yaml
	// .../config/scenarios/scenar.yaml
	// .../config/collections/linux.yaml //file is empty

	if len(subs) < 2 {
		return nil, fmt.Errorf("path is too short: %s (%d)", path, len(subs))
	}

	// this can be in any number of subdirs, we join them to compose the item name

	ftype := subs[0]
	stage := ""
	fname := strings.Join(subs[1:], "/")

	if ftype == PARSERS || ftype == POSTOVERFLOWS {
		stage = subs[1]
		fname = strings.Join(subs[2:], "/")
	}

	spec := itemSpec{
		path:    path,
		inhub:   false,
		ftype:   ftype,
		stage:   stage,
		fauthor: "",
		fname:   fname,
	}

	return &spec, nil
}

func newItemSpec(path, hubDir, installDir string) (*itemSpec, error) {
	var (
		spec *itemSpec
		err  error
	)

	if subs := relativePathComponents(path, hubDir); len(subs) > 0 {
		spec, err = newHubItemSpec(path, subs)
		if err != nil {
			return nil, err
		}
	} else if subs := relativePathComponents(path, installDir); len(subs) > 0 {
		spec, err = newInstallItemSpec(path, subs)
		if err != nil {
			return nil, err
		}
	}

	if spec == nil {
		return nil, fmt.Errorf("file '%s' is not from hub '%s' nor from the configuration directory '%s'", path, hubDir, installDir)
	}

	// follow the link to see if it falls in the hub directory
	// if it's not a link, target == path
	spec.target, err = resolveSymlink(spec.path)
	if err != nil {
		// target does not exist, the user might have removed the file
		// or switched to a hub branch without it; or symlink loop
		return nil, err
	}

	targetInHub, err := isPathInside(spec.target, hubDir)
	if err != nil {
		return nil, ErrSkipPath
	}

	spec.local = !targetInHub

	return spec, nil
}

// sortedVersions returns the input data, sorted in reverse order (new, old) by semver.
func sortedVersions(raw []string) ([]string, error) {
	vs := make([]*semver.Version, len(raw))

	for idx, r := range raw {
		v, err := semver.NewVersion(r)
		if err != nil {
			// TODO: should catch this during index parsing
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

func newLocalItem(h *Hub, path string, spec *itemSpec) (*Item, error) {
	type localItemName struct {
		Name string `yaml:"name"`
	}

	_, fileName := filepath.Split(path)

	item := &Item{
		hub:      h,
		Name:     spec.fname,
		Stage:    spec.stage,
		Type:     spec.ftype,
		FileName: fileName,
		State: ItemState{
			LocalPath: path,
			local:     true,
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
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}

	if itemName.Name != "" {
		item.Name = itemName.Name
	}

	return item, nil
}

// A sentinel to skip regular files because "nil, nil" is ambiguous. Returning SkipDir with files would skip the rest of the directory.
var ErrSkipPath = errors.New("sentinel")

func (h *Hub) itemVisit(path string, f os.DirEntry, err error) (*itemSpec, error) {
	if err != nil {
		h.logger.Debugf("while syncing hub dir: %s", err)
		// there is a path error, we ignore the file
		return nil, ErrSkipPath
	}

	// permission errors, files removed while reading, etc.
	if f == nil {
		return nil, ErrSkipPath
	}

	// only happens if the current working directory was removed (!)
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	if f.IsDir() {
		// if a directory starts with a dot, we don't traverse it
		// - single dot prefix is hidden by unix convention
		// - double dot prefix is used by k8s to mount config maps
		if strings.HasPrefix(f.Name(), ".") {
			h.logger.Tracef("skipping hidden directory %s", path)
			return nil, filepath.SkipDir
		}

		// keep traversing
		return nil, nil
	}

	// we only care about YAML files
	if !isYAMLFileName(f.Name()) {
		return nil, ErrSkipPath
	}

	spec, err := newItemSpec(path, h.local.HubDir, h.local.InstallDir)
	if err != nil {
		h.logger.Warningf("Ignoring file %s: %s", path, err)
		return nil, ErrSkipPath
	}

	return spec, nil
}

func updateNonLocalItem(h *Hub, path string, spec *itemSpec, symlinkTarget string) (*Item, error) {
	// look for the matching index entry
	tot := 0
	for range h.GetItemMap(spec.ftype) {
		tot++
	}

	for _, item := range h.GetItemMap(spec.ftype) {
		if item.Stage != spec.stage {
			continue
		}

		// Downloaded item, in the hub dir.
		if spec.inhub {
			// not the item we're looking for
			if !item.validPath(spec.fauthor, spec.fname) {
				continue
			}

			src, err := item.DownloadPath()
			if err != nil {
				return nil, err
			}

			if spec.path == src {
				h.logger.Tracef("marking %s as downloaded", item.Name)
				item.State.Downloaded = true
			}
		} else if !hasPathSuffix(symlinkTarget, item.RemotePath) {
			// wrong file
			// <type>/<stage>/<author>/<name>.yaml
			continue
		}

		err := item.setVersionState(spec.path, spec.inhub)
		if err != nil {
			return nil, err
		}

		return item, nil
	}

	return nil, nil
}

// addItemFromSpec adds an item to the hub based on the spec, or updates it if already present.
//
// When the item is:
//
// Local - an itemSpec instance is created while scanning the install directory
// and an Item instance will be added to the hub.items map.
//
// Not downloaded, not installed - an Item instance is already on hub.items (decoded from index) and left untouched.
//
// Downloaded, not installed - an Item instance is on hub.items (decoded from index) and an itemSpec instance is created
// to complete it (i.e. set version and state flags).
//
// Downloaded, installed - an Item instance is on hub.items and is complemented with two itemSpecs: one from the file
// on the hub directory, one from the link in the install directory.
func (h *Hub) addItemFromSpec(spec *itemSpec) error {
	var (
		item *Item
		err  error
	)

	// Local item: links outside the hub directory.
	// We add it, or overwrite the existing one if it happened to have the same name.
	if spec.local {
		item, err = newLocalItem(h, spec.path, spec)
		if err != nil {
			return err
		}

		// we now have the name declared in the file (for local),
		// see if there's another installed item of the same name
		theOtherItem := h.GetItem(spec.ftype, item.Name)
		if theOtherItem != nil {
			if theOtherItem.State.Installed {
				h.logger.Warnf("multiple %s named %s: ignoring %s", spec.ftype, item.Name, theOtherItem.State.LocalPath)
			}
		}
	} else {
		item, err = updateNonLocalItem(h, spec.path, spec, spec.target)
		if err != nil {
			return err
		}

		item.State.LocalPath = spec.path
	}

	if item == nil {
		h.logger.Infof("Ignoring file %s of type %s", spec.path, spec.ftype)
		return nil
	}

	h.addItem(item)

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

	for sub := range i.CurrentDependencies().SubItems(i.hub) {
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
			warn = append(warn, fmt.Sprintf("%s is outdated because of %s", i.Name, sub.FQName()))

			continue
		}

		i.hub.logger.Tracef("checking for %s - tainted:%t uptodate:%t", sub.Name, i.State.Tainted, i.State.UpToDate)
	}

	return warn
}

// syncDir scans a directory for items, and updates the Hub state accordingly.
func (h *Hub) syncDir(dir string) error {
	specs := []*itemSpec{}

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
			continue
		}

		// wrap itemVisit to collect spec results
		specCollector := func(path string, f os.DirEntry, err error) error {
			spec, err := h.itemVisit(path, f, err)
			if err == nil && spec != nil {
				specs = append(specs, spec)
			}

			if errors.Is(err, ErrSkipPath) {
				return nil
			}

			return err
		}

		if err = filepath.WalkDir(cpath, specCollector); err != nil {
			return err
		}
	}

	// add non-local items first, so they can find the place in the index
	// before it's overridden by local items in case of name collision
	for _, spec := range specs {
		if spec.local {
			continue
		}

		if err := h.addItemFromSpec(spec); err != nil {
			return err
		}
	}

	for _, spec := range specs {
		if !spec.local {
			continue
		}

		if err := h.addItemFromSpec(spec); err != nil {
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
	// add downloaded files first, so they can find the place in the index
	// before it's overridden by local items in case of name collision
	if err := h.syncDir(h.local.HubDir); err != nil {
		return fmt.Errorf("failed to sync %s: %w", h.local.HubDir, err)
	}

	if err := h.syncDir(h.local.InstallDir); err != nil {
		return fmt.Errorf("failed to sync %s: %w", h.local.InstallDir, err)
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

	i.State.LocalHash, err = downloader.SHA256(path)
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
