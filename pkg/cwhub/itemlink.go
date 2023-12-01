package cwhub

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// createInstallLink creates a symlink between the actual config file at hub.HubDir and hub.ConfigDir.
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

// removeInstallLink removes the symlink to the downloaded content.
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
