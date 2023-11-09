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

	return nil
}

// purge removes the actual config file that was downloaded
func (i *Item) purge() error {
	itempath := i.hub.local.HubDir + "/" + i.RemotePath

	// disable hub file
	if err := os.Remove(itempath); err != nil {
		return fmt.Errorf("while removing file: %w", err)
	}

	i.Downloaded = false
	log.Infof("Removed source file [%s]: %s", i.Name, itempath)

	return nil
}

// disable removes the symlink to the downloaded content, also removes the content if purge is true
func (i *Item) disable(purge bool, force bool) error {
	// XXX: should return the number of disabled/purged items to inform the upper layer whether to reload or not
	var err error

	// already disabled, noop unless purge
	if !i.Installed {
		if purge {
			err = i.purge()
			if err != nil {
				return err
			}
		}

		return nil
	}

	if i.IsLocal() {
		return fmt.Errorf("%s isn't managed by hub. Please delete manually", i.Name)
	}

	if i.Tainted && !force {
		return fmt.Errorf("%s is tainted, use '--force' to overwrite", i.Name)
	}

	// disable sub-items if any - it's a collection
	for _, sub := range i.SubItems() {
		// XXX: we do this already when syncing, do we really need to do consistency checks here and there?
		val, ok := i.hub.Items[sub.Type][sub.Name]
		if !ok {
			log.Errorf("Referred %s %s in collection %s doesn't exist.", sub.Type, sub.Name, i.Name)
			continue
		}

		// check if the item doesn't belong to another collection before removing it
		toRemove := true

		for _, collection := range val.BelongsToCollections {
			if collection != i.Name {
				toRemove = false
				break
			}
		}

		if toRemove {
			if err = val.disable(purge, force); err != nil {
				return fmt.Errorf("while disabling %s: %w", sub.Name, err)
			}
		} else {
			log.Infof("%s was not removed because it belongs to another collection", val.Name)
		}
	}

	syml, err := filepath.Abs(i.hub.local.InstallDir + "/" + i.Type + "/" + i.Stage + "/" + i.FileName)
	if err != nil {
		return err
	}

	stat, err := os.Lstat(syml)
	if os.IsNotExist(err) {
		// we only accept to "delete" non existing items if it's a forced purge
		if !purge && !force {
			return fmt.Errorf("can't delete %s: %s doesn't exist", i.Name, syml)
		}
	} else {
		// if it's managed by hub, it's a symlink to csconfig.GConfig.hub.HubDir / ...
		if stat.Mode()&os.ModeSymlink == 0 {
			log.Warningf("%s (%s) isn't a symlink, can't disable", i.Name, syml)
			return fmt.Errorf("%s isn't managed by hub", i.Name)
		}

		hubpath, err := os.Readlink(syml)
		if err != nil {
			return fmt.Errorf("while reading symlink: %w", err)
		}

		absPath, err := filepath.Abs(i.hub.local.HubDir + "/" + i.RemotePath)
		if err != nil {
			return fmt.Errorf("while abs path: %w", err)
		}

		if hubpath != absPath {
			log.Warningf("%s (%s) isn't a symlink to %s", i.Name, syml, absPath)
			return fmt.Errorf("%s isn't managed by hub", i.Name)
		}

		// remove the symlink
		if err = os.Remove(syml); err != nil {
			return fmt.Errorf("while removing symlink: %w", err)
		}

		log.Infof("Removed symlink [%s]: %s", i.Name, syml)
	}

	i.Installed = false

	if purge {
		err = i.purge()
		if err != nil {
			return err
		}
	}

	return nil
}
