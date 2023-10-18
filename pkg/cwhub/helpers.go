package cwhub

import (
	"fmt"
	"path/filepath"

	"github.com/enescakir/emoji"
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
)

// chooseHubBranch returns the branch name to use for the hub
// It can be "master" or branch corresponding to the current crowdsec version
func chooseHubBranch() string {
	latest, err := cwversion.Latest()
	if err != nil {
		log.Warningf("Unable to retrieve latest crowdsec version: %s, defaulting to master", err)
		return "master"
	}

	csVersion := cwversion.VersionStrip()
	if csVersion == latest {
		log.Debugf("current version is equal to latest (%s)", csVersion)
		return "master"
	}

	// if current version is greater than the latest we are in pre-release
	if semver.Compare(csVersion, latest) == 1 {
		log.Debugf("Your current crowdsec version seems to be a pre-release (%s)", csVersion)
		return "master"
	}

	if csVersion == "" {
		log.Warning("Crowdsec version is not set, using master branch for the hub")
		return "master"
	}

	log.Warnf("Crowdsec is not the latest version. "+
		"Current version is '%s' and the latest stable version is '%s'. Please update it!",
		csVersion, latest)

	log.Warnf("As a result, you will not be able to use parsers/scenarios/collections "+
		"added to Crowdsec Hub after CrowdSec %s", latest)

	return csVersion
}

// SetHubBranch sets the package variable that points to the hub branch.
func SetHubBranch() {
	// a branch is already set, or specified from the flags
	if HubBranch != "" {
		return
	}

	// use the branch corresponding to the crowdsec version
	HubBranch = chooseHubBranch()

	log.Debugf("Using branch '%s' for the hub", HubBranch)
}

// InstallItem installs an item from the hub
func (h *Hub) InstallItem(name string, itemType string, force bool, downloadOnly bool) error {
	item := h.GetItem(itemType, name)
	if item == nil {
		return fmt.Errorf("unable to retrieve item: %s", name)
	}

	if downloadOnly && item.Downloaded && item.UpToDate {
		log.Warningf("%s is already downloaded and up-to-date", item.Name)

		if !force {
			return nil
		}
	}

	err := h.DownloadLatest(item, force, true)
	if err != nil {
		return fmt.Errorf("while downloading %s: %w", item.Name, err)
	}

	if err = h.AddItem(itemType, *item); err != nil {
		return fmt.Errorf("while adding %s: %w", item.Name, err)
	}

	if downloadOnly {
		log.Infof("Downloaded %s to %s", item.Name, filepath.Join(h.cfg.HubDir, item.RemotePath))
		return nil
	}

	err = h.EnableItem(item)
	if err != nil {
		return fmt.Errorf("while enabling %s: %w", item.Name, err)
	}

	if err := h.AddItem(itemType, *item); err != nil {
		return fmt.Errorf("while adding %s: %w", item.Name, err)
	}

	log.Infof("Enabled %s", item.Name)

	return nil
}

// RemoveItem removes one - or all - the items from the hub
func (h *Hub) RemoveMany(itemType string, name string, all bool, purge bool, forceAction bool) error {
	if name != "" {
		item := h.GetItem(itemType, name)
		if item == nil {
			return fmt.Errorf("can't find '%s' in %s", name, itemType)
		}

		err := h.DisableItem(item, purge, forceAction)

		if err != nil {
			return fmt.Errorf("unable to disable %s: %w", item.Name, err)
		}

		if err = h.AddItem(itemType, *item); err != nil {
			return fmt.Errorf("unable to add %s: %w", item.Name, err)
		}

		return nil
	}

	if !all {
		return fmt.Errorf("removing item: no item specified")
	}

	disabled := 0

	// remove all
	for _, v := range h.GetItemMap(itemType) {
		if !v.Installed {
			continue
		}

		err := h.DisableItem(&v, purge, forceAction)
		if err != nil {
			return fmt.Errorf("unable to disable %s: %w", v.Name, err)
		}

		if err := h.AddItem(itemType, v); err != nil {
			return fmt.Errorf("unable to add %s: %w", v.Name, err)
		}
		disabled++
	}

	log.Infof("Disabled %d items", disabled)

	return nil
}

// UpgradeConfig upgrades an item from the hub
func (h *Hub) UpgradeConfig(itemType string, name string, force bool) error {
	updated := 0
	found := false

	for _, v := range h.GetItemMap(itemType) {
		if name != "" && name != v.Name {
			continue
		}

		if !v.Installed {
			log.Tracef("skip %s, not installed", v.Name)
			continue
		}

		if !v.Downloaded {
			log.Warningf("%s: not downloaded, please install.", v.Name)
			continue
		}

		found = true

		if v.UpToDate {
			log.Infof("%s: up-to-date", v.Name)

			if err := h.DownloadDataIfNeeded(v, force); err != nil {
				return fmt.Errorf("%s: download failed: %w", v.Name, err)
			}

			if !force {
				continue
			}
		}

		if err := h.DownloadLatest(&v, force, true); err != nil {
			return fmt.Errorf("%s: download failed: %w", v.Name, err)
		}

		if !v.UpToDate {
			if v.Tainted {
				log.Infof("%v %s is tainted, --force to overwrite", emoji.Warning, v.Name)
			} else if v.Local {
				log.Infof("%v %s is local", emoji.Prohibited, v.Name)
			}
		} else {
			// this is used while scripting to know if the hub has been upgraded
			// and a configuration reload is required
			fmt.Printf("updated %s\n", v.Name)
			log.Infof("%v %s : updated", emoji.Package, v.Name)
			updated++
		}

		if err := h.AddItem(itemType, v); err != nil {
			return fmt.Errorf("unable to add %s: %w", v.Name, err)
		}
	}

	if !found && name == "" {
		log.Infof("No %s installed, nothing to upgrade", itemType)
	} else if !found {
		log.Errorf("can't find '%s' in %s", name, itemType)
	} else if updated == 0 && found {
		if name == "" {
			log.Infof("All %s are already up-to-date", itemType)
		} else {
			log.Infof("Item '%s' is up-to-date", name)
		}
	} else if updated != 0 {
		log.Infof("Upgraded %d items", updated)
	}

	return nil
}
