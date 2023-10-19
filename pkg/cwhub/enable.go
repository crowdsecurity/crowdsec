package cwhub

// Enable/disable items already installed (no downloading here)
// This file is not named install.go to avoid confusion with the functions in helpers.go

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// creates symlink between actual config file at hub.HubDir and hub.ConfigDir
// Handles collections recursively
func (h *Hub) EnableItem(target *Item) error {
	var err error

	parentDir := filepath.Clean(h.cfg.InstallDir + "/" + target.Type + "/" + target.Stage + "/")

	// create directories if needed
	if target.Installed {
		if target.Tainted {
			return fmt.Errorf("%s is tainted, won't enable unless --force", target.Name)
		}

		if target.Local {
			return fmt.Errorf("%s is local, won't enable", target.Name)
		}

		// if it's a collection, check sub-items even if the collection file itself is up-to-date
		if target.UpToDate && target.Type != COLLECTIONS {
			log.Tracef("%s is installed and up-to-date, skip.", target.Name)
			return nil
		}
	}

	if _, err = os.Stat(parentDir); os.IsNotExist(err) {
		log.Infof("%s doesn't exist, create", parentDir)

		if err = os.MkdirAll(parentDir, os.ModePerm); err != nil {
			return fmt.Errorf("while creating directory: %w", err)
		}
	}

	// install sub-items if it's a collection
	if target.Type == COLLECTIONS {
		for idx, ptr := range [][]string{target.Parsers, target.PostOverflows, target.Scenarios, target.Collections} {
			ptrtype := ItemTypes[idx]
			for _, p := range ptr {
				val, ok := h.Items[ptrtype][p]
				if !ok {
					return fmt.Errorf("required %s %s of %s doesn't exist, abort", ptrtype, p, target.Name)
				}

				err = h.EnableItem(&val)
				if err != nil {
					return fmt.Errorf("while installing %s: %w", p, err)
				}
			}
		}
	}

	// check if file already exists where it should in configdir (eg /etc/crowdsec/collections/)
	if _, err = os.Lstat(parentDir + "/" + target.FileName); !os.IsNotExist(err) {
		log.Infof("%s already exists.", parentDir+"/"+target.FileName)
		return nil
	}

	// hub.ConfigDir + target.RemotePath
	srcPath, err := filepath.Abs(h.cfg.HubDir + "/" + target.RemotePath)
	if err != nil {
		return fmt.Errorf("while getting source path: %w", err)
	}

	dstPath, err := filepath.Abs(parentDir + "/" + target.FileName)
	if err != nil {
		return fmt.Errorf("while getting destination path: %w", err)
	}

	if err = os.Symlink(srcPath, dstPath); err != nil {
		return fmt.Errorf("while creating symlink from %s to %s: %w", srcPath, dstPath, err)
	}

	log.Infof("Enabled %s : %s", target.Type, target.Name)
	target.Installed = true
	h.Items[target.Type][target.Name] = *target

	return nil
}

func (h *Hub) purgeItem(target Item) (Item, error) {
	itempath := h.cfg.HubDir + "/" + target.RemotePath

	// disable hub file
	if err := os.Remove(itempath); err != nil {
		return target, fmt.Errorf("while removing file: %w", err)
	}

	target.Downloaded = false
	log.Infof("Removed source file [%s]: %s", target.Name, itempath)
	h.Items[target.Type][target.Name] = target

	return target, nil
}

// DisableItem to disable an item managed by the hub, removes the symlink if purge is true
func (h *Hub) DisableItem(target *Item, purge bool, force bool) error {
	var err error

	// already disabled, noop unless purge
	if !target.Installed {
		if purge {
			*target, err = h.purgeItem(*target)
			if err != nil {
				return err
			}
		}

		return nil
	}

	if target.Local {
		return fmt.Errorf("%s isn't managed by hub. Please delete manually", target.Name)
	}

	if target.Tainted && !force {
		return fmt.Errorf("%s is tainted, use '--force' to overwrite", target.Name)
	}

	// for a COLLECTIONS, disable sub-items
	if target.Type == COLLECTIONS {
		for idx, ptr := range [][]string{target.Parsers, target.PostOverflows, target.Scenarios, target.Collections} {
			ptrtype := ItemTypes[idx]
			for _, p := range ptr {
				if val, ok := h.Items[ptrtype][p]; ok {
					// check if the item doesn't belong to another collection before removing it
					toRemove := true

					for _, collection := range val.BelongsToCollections {
						if collection != target.Name {
							toRemove = false
							break
						}
					}

					if toRemove {
						err = h.DisableItem(&val, purge, force)
						if err != nil {
							return fmt.Errorf("while disabling %s: %w", p, err)
						}
					} else {
						log.Infof("%s was not removed because it belongs to another collection", val.Name)
					}
				} else {
					log.Errorf("Referred %s %s in collection %s doesn't exist.", ptrtype, p, target.Name)
				}
			}
		}
	}

	syml, err := filepath.Abs(h.cfg.InstallDir + "/" + target.Type + "/" + target.Stage + "/" + target.FileName)
	if err != nil {
		return err
	}

	stat, err := os.Lstat(syml)
	if os.IsNotExist(err) {
		// we only accept to "delete" non existing items if it's a forced purge
		if !purge && !force {
			return fmt.Errorf("can't delete %s : %s doesn't exist", target.Name, syml)
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

		absPath, err := filepath.Abs(h.cfg.HubDir + "/" + target.RemotePath)
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

		log.Infof("Removed symlink [%s] : %s", target.Name, syml)
	}

	target.Installed = false

	if purge {
		*target, err = h.purgeItem(*target)
		if err != nil {
			return err
		}
	}

	h.Items[target.Type][target.Name] = *target

	return nil
}
