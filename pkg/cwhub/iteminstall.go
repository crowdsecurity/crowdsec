package cwhub

import (
	"fmt"
)

// enable enables the item by creating a symlink to the downloaded content, and also enables sub-items.
func (i *Item) enable() error {
	if i.State.Installed {
		if i.State.Tainted {
			return fmt.Errorf("%s is tainted, won't enable unless --force", i.Name)
		}

		if i.State.IsLocal() {
			return fmt.Errorf("%s is local, won't enable", i.Name)
		}

		// if it's a collection, check sub-items even if the collection file itself is up-to-date
		if i.State.UpToDate && !i.HasSubItems() {
			i.hub.logger.Tracef("%s is installed and up-to-date, skip.", i.Name)
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

	i.hub.logger.Infof("Enabled %s: %s", i.Type, i.Name)
	i.State.Installed = true

	return nil
}

// Install installs the item from the hub, downloading it if needed.
func (i *Item) Install(force bool, downloadOnly bool) error {
	if downloadOnly && i.State.Downloaded && i.State.UpToDate {
		i.hub.logger.Infof("%s is already downloaded and up-to-date", i.Name)

		if !force {
			return nil
		}
	}

	filePath, err := i.downloadLatest(force, true)
	if err != nil {
		return fmt.Errorf("while downloading %s: %w", i.Name, err)
	}

	if downloadOnly {
		i.hub.logger.Infof("Downloaded %s to %s", i.Name, filePath)
		return nil
	}

	if err := i.enable(); err != nil {
		return fmt.Errorf("while enabling %s: %w", i.Name, err)
	}

	i.hub.logger.Infof("Enabled %s", i.Name)

	return nil
}
