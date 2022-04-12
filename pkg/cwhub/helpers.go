package cwhub

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/enescakir/emoji"
	log "github.com/sirupsen/logrus"
)

func InstallItem(csConfig *csconfig.Config, name string, obtype string, force bool, downloadOnly bool) error {
	it := GetItem(obtype, name)
	if it == nil {
		return fmt.Errorf("unable to retrieve item : %s", name)
	}
	item := *it
	if downloadOnly && item.Downloaded && item.UpToDate {
		log.Warningf("%s is already downloaded and up-to-date", item.Name)
		if !force {
			return nil
		}
	}
	item, err := DownloadLatest(csConfig.Hub, item, force, false)
	if err != nil {
		return fmt.Errorf("error while downloading %s : %v", item.Name, err)
	}
	AddItem(obtype, item)
	if downloadOnly {
		log.Infof("Downloaded %s to %s", item.Name, csConfig.Hub.HubDir+"/"+item.RemotePath)
		return nil
	}
	item, err = EnableItem(csConfig.Hub, item)
	if err != nil {
		return fmt.Errorf("error while enabling  %s : %v.", item.Name, err)
	}
	AddItem(obtype, item)
	log.Infof("Enabled %s", item.Name)

	return nil
}

func RemoveMany(csConfig *csconfig.Config, itemType string, name string, all bool, purge bool, forceAction bool) {
	var err error
	var disabled int
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
		AddItem(itemType, item)
		return
	} else if name == "" && all {
		for _, v := range GetItemMap(itemType) {
			v, err = DisableItem(csConfig.Hub, v, purge, forceAction)
			if err != nil {
				log.Fatalf("unable to disable %s : %v", v.Name, err)
			}
			AddItem(itemType, v)
			disabled++
		}
	}
	if name != "" && !all {
		log.Errorf("%s not found", name)
		return
	}
	log.Infof("Disabled %d items", disabled)
}

func UpgradeConfig(csConfig *csconfig.Config, itemType string, name string, force bool) {
	var err error
	var updated int
	var found bool

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
		AddItem(itemType, v)
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
