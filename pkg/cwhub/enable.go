package cwhub

// Enable/disable items already downloaded

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// enable creates a symlink between actual config file at hub.HubDir and hub.ConfigDir
// Handles collections recursively
func (i *Item) enable() error {
	parentDir := filepath.Clean(i.hub.local.InstallDir + "/" + i.Type + "/" + i.Stage + "/")

	// create directories if needed
	if i.Installed {
		if i.Tainted {
			return fmt.Errorf("%s is tainted, won't enable unless --force", i.Name)
		}

		if i.IsLocal() {
			return fmt.Errorf("%s is local, won't enable", i.Name)
		}

		// if it's a collection, check sub-items even if the collection file itself is up-to-date
		if i.UpToDate && !i.HasSubItems() {
			log.Tracef("%s is installed and up-to-date, skip.", i.Name)
			return nil
		}
	}

	if _, err := os.Stat(parentDir); os.IsNotExist(err) {
		log.Infof("%s doesn't exist, create", parentDir)

		if err = os.MkdirAll(parentDir, os.ModePerm); err != nil {
			return fmt.Errorf("while creating directory: %w", err)
		}
	}

	// install sub-items if any
	for _, sub := range i.SubItems() {
		val, ok := i.hub.Items[sub.Type][sub.Name]
		if !ok {
			return fmt.Errorf("required %s %s of %s doesn't exist, abort", sub.Type, sub.Name, i.Name)
		}

		if err := val.enable(); err != nil {
			return fmt.Errorf("while installing %s: %w", sub.Name, err)
		}
	}

	// check if file already exists where it should in configdir (eg /etc/crowdsec/collections/)
	if _, err := os.Lstat(parentDir + "/" + i.FileName); !os.IsNotExist(err) {
		log.Infof("%s already exists.", parentDir+"/"+i.FileName)
		return nil
	}

	// hub.ConfigDir + target.RemotePath
	srcPath, err := filepath.Abs(i.hub.local.HubDir + "/" + i.RemotePath)
	if err != nil {
		return fmt.Errorf("while getting source path: %w", err)
	}

	dstPath, err := filepath.Abs(parentDir + "/" + i.FileName)
	if err != nil {
		return fmt.Errorf("while getting destination path: %w", err)
	}

	if err = os.Symlink(srcPath, dstPath); err != nil {
		return fmt.Errorf("while creating symlink from %s to %s: %w", srcPath, dstPath, err)
	}

	log.Infof("Enabled %s: %s", i.Type, i.Name)
	i.Installed = true
	i.hub.Items[i.Type][i.Name] = *i

	return nil
}

func (i *Item) purge() error {
	itempath := i.hub.local.HubDir + "/" + i.RemotePath

	// disable hub file
	if err := os.Remove(itempath); err != nil {
		return fmt.Errorf("while removing file: %w", err)
	}

	i.Downloaded = false
	log.Infof("Removed source file [%s]: %s", i.Name, itempath)
	i.hub.Items[i.Type][i.Name] = *i

	return nil
}

// disableItem to disable an item managed by the hub, removes the symlink if purge is true
func (h *Hub) disableItem(target *Item, purge bool, force bool) error {
	// XXX: should return the number of disabled/purged items to inform the upper layer whether to reload or not
	var err error

	// already disabled, noop unless purge
	if !target.Installed {
		if purge {
			err = target.purge()
			if err != nil {
				return err
			}
		}

		return nil
	}

	if target.IsLocal() {
		return fmt.Errorf("%s isn't managed by hub. Please delete manually", target.Name)
	}

	if target.Tainted && !force {
		return fmt.Errorf("%s is tainted, use '--force' to overwrite", target.Name)
	}

	// disable sub-items if any - it's a collection
	for _, sub := range target.SubItems() {
		// XXX: we do this already when syncing, do we really need to do consistency checks here and there?
		val, ok := h.Items[sub.Type][sub.Name]
		if !ok {
			log.Errorf("Referred %s %s in collection %s doesn't exist.", sub.Type, sub.Name, target.Name)
			continue
		}

		// check if the item doesn't belong to another collection before removing it
		toRemove := true

		for _, collection := range val.BelongsToCollections {
			if collection != target.Name {
				toRemove = false
				break
			}
		}

		if toRemove {
			if err = h.disableItem(&val, purge, force); err != nil {
				return fmt.Errorf("while disabling %s: %w", sub.Name, err)
			}
		} else {
			log.Infof("%s was not removed because it belongs to another collection", val.Name)
		}
	}

	syml, err := filepath.Abs(h.local.InstallDir + "/" + target.Type + "/" + target.Stage + "/" + target.FileName)
	if err != nil {
		return err
	}

	stat, err := os.Lstat(syml)
	if os.IsNotExist(err) {
		// we only accept to "delete" non existing items if it's a forced purge
		if !purge && !force {
			return fmt.Errorf("can't delete %s: %s doesn't exist", target.Name, syml)
		}
	} else {
		// if it's managed by hub, it's a symlink to csconfig.GConfig.hub.HubDir / ...
		if stat.Mode()&os.ModeSymlink == 0 {
			log.Warningf("%s (%s) isn't a symlink, can't disable", target.Name, syml)
			return fmt.Errorf("%s isn't managed by hub", target.Name)
		}

		hubpath, err := os.Readlink(syml)
		if err != nil {
			return fmt.Errorf("while reading symlink: %w", err)
		}

		absPath, err := filepath.Abs(h.local.HubDir + "/" + target.RemotePath)
		if err != nil {
			return fmt.Errorf("while abs path: %w", err)
		}

		if hubpath != absPath {
			log.Warningf("%s (%s) isn't a symlink to %s", target.Name, syml, absPath)
			return fmt.Errorf("%s isn't managed by hub", target.Name)
		}

		// remove the symlink
		if err = os.Remove(syml); err != nil {
			return fmt.Errorf("while removing symlink: %w", err)
		}

		log.Infof("Removed symlink [%s]: %s", target.Name, syml)
	}

	target.Installed = false

	if purge {
		err = target.purge()
		if err != nil {
			return err
		}
	}

	h.Items[target.Type][target.Name] = *target

	return nil
}
