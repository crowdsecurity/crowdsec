package cwhub

// Enable/disable items already downloaded

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// installLink returns the location of the symlink to the actual config file (eg. /etc/crowdsec/collections/xyz.yaml)
func (i *Item) installLink() string {
	return filepath.Join(i.hub.local.InstallDir, i.Type, i.Stage, i.FileName)
}

// makeLink creates a symlink between the actual config file at hub.HubDir and hub.ConfigDir
func (i *Item) createInstallLink() error {
	dest, err := filepath.Abs(i.installLink())
	if err != nil {
		return err
	}

	destDir := filepath.Dir(dest)
	if err = os.MkdirAll(destDir, os.ModePerm); err != nil {
		return fmt.Errorf("while creating %s: %w", destDir, err)
	}

	if _, err = os.Lstat(dest); !os.IsNotExist(err) {
		log.Infof("%s already exists.", dest)
		return nil
	}

	src, err := filepath.Abs(filepath.Join(i.hub.local.HubDir, i.RemotePath))
	if err != nil {
		return err
	}

	if err = os.Symlink(src, dest); err != nil {
		return fmt.Errorf("while creating symlink from %s to %s: %w", src, dest, err)
	}

	return nil
}

// enable enables the item by creating a symlink to the downloaded content, and also enables sub-items
func (i *Item) enable() error {
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

	for _, sub := range i.SubItems() {
		if err := sub.enable(); err != nil {
			return fmt.Errorf("while installing %s: %w", sub.Name, err)
		}
	}

	if err := i.createInstallLink(); err != nil {
		return err
	}

	log.Infof("Enabled %s: %s", i.Type, i.Name)
	i.Installed = true

	return nil
}

// purge removes the actual config file that was downloaded
func (i *Item) purge() error {
	if !i.Downloaded {
		log.Infof("removing %s: not downloaded -- no need to remove", i.Name)
		return nil
	}

	src := filepath.Join(i.hub.local.HubDir, i.RemotePath)

	if err := os.Remove(src); err != nil {
		if os.IsNotExist(err) {
			log.Debugf("%s doesn't exist, no need to remove", src)
			return nil
		}

		return fmt.Errorf("while removing file: %w", err)
	}

	i.Downloaded = false
	log.Infof("Removed source file [%s]: %s", i.Name, src)

	return nil
}

func (i *Item) removeInstallLink() error {
	syml, err := filepath.Abs(i.installLink())
	if err != nil {
		return err
	}

	stat, err := os.Lstat(syml)
	if err != nil {
		return err
	}

	// if it's managed by hub, it's a symlink to csconfig.GConfig.hub.HubDir / ...
	if stat.Mode()&os.ModeSymlink == 0 {
		log.Warningf("%s (%s) isn't a symlink, can't disable", i.Name, syml)
		return fmt.Errorf("%s isn't managed by hub", i.Name)
	}

	hubpath, err := os.Readlink(syml)
	if err != nil {
		return fmt.Errorf("while reading symlink: %w", err)
	}

	src, err := filepath.Abs(i.hub.local.HubDir + "/" + i.RemotePath)
	if err != nil {
		return err
	}

	if hubpath != src {
		log.Warningf("%s (%s) isn't a symlink to %s", i.Name, syml, src)
		return fmt.Errorf("%s isn't managed by hub", i.Name)
	}

	if err := os.Remove(syml); err != nil {
		return fmt.Errorf("while removing symlink: %w", err)
	}

	log.Infof("Removed symlink [%s]: %s", i.Name, syml)

	return nil
}

// disable removes the symlink to the downloaded content, also removes the content if purge is true
func (i *Item) disable(purge bool, force bool) error {
	// XXX: should return the number of disabled/purged items to inform the upper layer whether to reload or not
	err := i.removeInstallLink()
	if os.IsNotExist(err) {
		if !purge && !force {
			return fmt.Errorf("link %s does not exist (override with --force or --purge)", i.installLink())
		}
	} else if err != nil {
		return err
	}

	i.Installed = false

	if purge {
		if err := i.purge(); err != nil {
			return err
		}
	}

	return nil
}
