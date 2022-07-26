package cwhub

import (
	"fmt"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/enescakir/emoji"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"
)

// pick a hub branch corresponding to the current crowdsec version.
func chooseHubBranch() (string, error) {
	latest, err := cwversion.Latest()
	if err != nil {
		return "master", err
	}

	csVersion := cwversion.VersionStrip()
	if csVersion == latest {
		return "master", nil
	}

	// if current version is greater than the latest we are in pre-release
	if semver.Compare(csVersion, latest) == 1 {
		log.Debugf("Your current crowdsec version seems to be a pre-release (%s)", csVersion)
		return "master", nil
	}

	if csVersion == "" {
		log.Warning("Crowdsec version is not set, using master branch for the hub")
		return "master", nil
	}

	log.Warnf("Crowdsec is not the latest version. "+
		"Current version is '%s' and the latest stable version is '%s'. Please update it!",
		csVersion, latest)
	log.Warnf("As a result, you will not be able to use parsers/scenarios/collections "+
		"added to Crowdsec Hub after CrowdSec %s", latest)
	return csVersion, nil
}

// SetHubBranch sets the package variable that points to the hub branch.
func SetHubBranch() error {
	// a branch is already set, or specified from the flags
	if HubBranch != "" {
		return nil
	}

	// use the branch corresponding to the crowdsec version
	branch, err := chooseHubBranch()
	if err != nil {
		return err
	}
	HubBranch = branch
	log.Debugf("Using branch '%s' for the hub", HubBranch)
	return nil
}

func InstallItem(csConfig *csconfig.Config, name string, obtype string, force bool, downloadOnly bool) error {
	it := GetItem(obtype, name)
	if it == nil {
		return fmt.Errorf("unable to retrieve item: %s", name)
	}

	item := *it
	if downloadOnly && item.Downloaded && item.UpToDate {
		log.Warningf("%s is already downloaded and up-to-date", item.Name)
		if !force {
			return nil
		}
	}

	item, err := DownloadLatest(csConfig.Hub, item, force, true)
	if err != nil {
		return errors.Wrapf(err, "while downloading %s", item.Name)
	}

	if err := AddItem(obtype, item); err != nil {
		return errors.Wrapf(err, "while adding %s", item.Name)
	}

	if downloadOnly {
		log.Infof("Downloaded %s to %s", item.Name, filepath.Join(csConfig.Hub.HubDir, item.RemotePath))
		return nil
	}

	item, err = EnableItem(csConfig.Hub, item)
	if err != nil {
		return errors.Wrapf(err, "while enabling %s", item.Name)
	}

	if err := AddItem(obtype, item); err != nil {
		return errors.Wrapf(err, "while adding %s", item.Name)
	}

	log.Infof("Enabled %s", item.Name)

	return nil
}

// XXX this must return errors instead of log.Fatal
func RemoveMany(csConfig *csconfig.Config, itemType string, name string, all bool, purge bool, forceAction bool) {
	var (
		err      error
		disabled int
	)

	if name != "" {
		it := GetItem(itemType, name)
		if it == nil {
			log.Fatalf("unable to retrieve: %s", name)
		}

		item := *it
		item, err = DisableItem(csConfig.Hub, item, purge, forceAction)
		if err != nil {
			log.Fatalf("unable to disable %s : %v", item.Name, err)
		}

		if err := AddItem(itemType, item); err != nil {
			log.Fatalf("unable to add %s: %v", item.Name, err)
		}
		return
	}

	if !all {
		log.Fatal("removing item: no item specified")
	}

	// remove all
	for _, v := range GetItemMap(itemType) {
		v, err = DisableItem(csConfig.Hub, v, purge, forceAction)
		if err != nil {
			log.Fatalf("unable to disable %s : %v", v.Name, err)
		}

		if err := AddItem(itemType, v); err != nil {
			log.Fatalf("unable to add %s: %v", v.Name, err)
		}
		disabled++
	}
	log.Infof("Disabled %d items", disabled)
}

func UpgradeConfig(csConfig *csconfig.Config, itemType string, name string, force bool) {
	var (
		err     error
		updated int
		found   bool
	)

	for _, v := range GetItemMap(itemType) {
		if name != "" && name != v.Name {
			continue
		}

		if !v.Installed {
			log.Tracef("skip %s, not installed", v.Name)
			continue
		}

		if !v.Downloaded {
			log.Warningf("%s : not downloaded, please install.", v.Name)
			continue
		}

		found = true

		if v.UpToDate {
			log.Infof("%s : up-to-date", v.Name)

			if err = DownloadDataIfNeeded(csConfig.Hub, v, force); err != nil {
				log.Fatalf("%s : download failed : %v", v.Name, err)
			}

			if !force {
				continue
			}
		}

		v, err = DownloadLatest(csConfig.Hub, v, force, true)
		if err != nil {
			log.Fatalf("%s : download failed : %v", v.Name, err)
		}

		if !v.UpToDate {
			if v.Tainted {
				log.Infof("%v %s is tainted, --force to overwrite", emoji.Warning, v.Name)
			} else if v.Local {
				log.Infof("%v %s is local", emoji.Prohibited, v.Name)
			}
		} else {
			log.Infof("%v %s : updated", emoji.Package, v.Name)
			updated++
		}

		if err := AddItem(itemType, v); err != nil {
			log.Fatalf("unable to add %s: %v", v.Name, err)
		}
	}

	if !found && name == "" {
		log.Infof("No %s installed, nothing to upgrade", itemType)
	} else if !found {
		log.Errorf("Item '%s' not found in hub", name)
	} else if updated == 0 && found {
		if name == "" {
			log.Infof("All %s are already up-to-date", itemType)
		} else {
			log.Infof("Item '%s' is up-to-date", name)
		}
	} else if updated != 0 {
		log.Infof("Upgraded %d items", updated)
	}
}
