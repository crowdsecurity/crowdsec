package cwhub

// Enable/disable items already downloaded

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// installPath returns the location of the symlink to the item in the hub, or the path of the item itself if it's local
// (eg. /etc/crowdsec/collections/xyz.yaml)
// raises an error if the path goes outside of the install dir
func (i *Item) installPath() (string, error) {
	p := i.Type
	if i.Stage != "" {
		p = filepath.Join(p, i.Stage)
	}

	return safePath(i.hub.local.InstallDir, filepath.Join(p, i.FileName))
}

// downloadPath returns the location of the actual config file in the hub
// (eg. /etc/crowdsec/hub/collections/author/xyz.yaml)
// raises an error if the path goes outside of the hub dir
func (i *Item) downloadPath() (string, error) {
	ret, err := safePath(i.hub.local.HubDir, i.RemotePath)
	if err != nil {
		return "", err
	}

	return ret, nil
}

// makeLink creates a symlink between the actual config file at hub.HubDir and hub.ConfigDir
func (i *Item) createInstallLink() error {
	dest, err := i.installPath()
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

	src, err := i.downloadPath()
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
	if i.State.Installed {
		if i.State.Tainted {
			return fmt.Errorf("%s is tainted, won't enable unless --force", i.Name)
		}

		if i.IsLocal() {
			return fmt.Errorf("%s is local, won't enable", i.Name)
		}

		// if it's a collection, check sub-items even if the collection file itself is up-to-date
		if i.State.UpToDate && !i.HasSubItems() {
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
	i.State.Installed = true

	return nil
}

// purge removes the actual config file that was downloaded
func (i *Item) purge() error {
	if !i.State.Downloaded {
		log.Infof("removing %s: not downloaded -- no need to remove", i.Name)
		return nil
	}

	src, err := i.downloadPath()
	if err != nil {
		return err
	}

	if err := os.Remove(src); err != nil {
		if os.IsNotExist(err) {
			log.Debugf("%s doesn't exist, no need to remove", src)
			return nil
		}

		return fmt.Errorf("while removing file: %w", err)
	}

	i.State.Downloaded = false
	log.Infof("Removed source file [%s]: %s", i.Name, src)

	return nil
}

// removeInstallLink removes the symlink to the downloaded content
func (i *Item) removeInstallLink() error {
	syml, err := i.installPath()
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

	src, err := i.downloadPath()
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

// disable removes the install link, and optionally the downloaded content
func (i *Item) disable(purge bool, force bool) error {
	// XXX: should return the number of disabled/purged items to inform the upper layer whether to reload or not
	err := i.removeInstallLink()
	if os.IsNotExist(err) {
		if !purge && !force {
			link, _ := i.installPath()
			return fmt.Errorf("link %s does not exist (override with --force or --purge)", link)
		}
	} else if err != nil {
		return err
	}

	i.State.Installed = false

	if purge {
		if err := i.purge(); err != nil {
			return err
		}
	}

	return nil
}
