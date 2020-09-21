package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/enescakir/emoji"
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v2"
)

func inSlice(s string, slice []string) bool {
	for _, str := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func indexOf(s string, slice []string) int {
	for i, elem := range slice {
		if s == elem {
			return i
		}
	}
	return -1
}

func setHubBranch() error {
	/*
		if no branch has been specified in flags for the hub, then use the one corresponding to crowdsec version
	*/

	if cwhub.HubBranch == "" {
		latest, err := cwversion.Latest()
		if err != nil {
			cwhub.HubBranch = "master"
			return err
		}

		if cwversion.Version == latest {
			cwhub.HubBranch = "master"
		} else if semver.Compare(cwversion.Version, latest) == 1 { // if current version is greater than the latest we are in pre-release
			log.Debugf("Your current crowdsec version seems to be a pre-release (%s)", cwversion.Version)
			cwhub.HubBranch = "master"
		} else {
			log.Warnf("Crowdsec is not the latest version. Current version is '%s' and latest version is '%s'. Please update it!", cwversion.Version, latest)
			log.Warnf("As a result, you will not be able to use parsers/scenarios/collections added to Crowdsec Hub after CrowdSec %s", latest)
			cwhub.HubBranch = cwversion.Version
		}
		log.Debugf("Using branch '%s' for the hub", cwhub.HubBranch)
	}
	return nil
}

func InstallItem(name string, obtype string) {
	it := cwhub.GetItem(obtype, name)
	if it == nil {
		log.Fatalf("unable to retrive item : %s", name)
	}
	item := *it
	if downloadOnly && item.Downloaded && item.UpToDate {
		log.Warningf("%s is already downloaded and up-to-date", item.Name)
		return
	}
	item, err := cwhub.DownloadLatest(csConfig.Cscli, item, forceInstall)
	if err != nil {
		log.Fatalf("error while downloading %s : %v", item.Name, err)
	}
	cwhub.AddItemMap(obtype, item)
	if downloadOnly {
		log.Infof("Downloaded %s to %s", item.Name, csConfig.Cscli.HubDir+"/"+item.RemotePath)
		return
	}
	item, err = cwhub.EnableItem(csConfig.Cscli, item)
	if err != nil {
		log.Fatalf("error while enabled %s : %v.", item.Name, err)
	}
	cwhub.AddItemMap(obtype, item)
	log.Infof("Enabled %s", item.Name)
	return
	log.Warningf("%s not found in hub index", name)
	/*iterate of pkg index data*/
}

func RemoveMany(ttype string, name string) {
	var err error
	var disabled int
	if name != "" {
		it := cwhub.GetItem(ttype, name)
		if it != nil {
			log.Fatalf("unable to retrieve: %s", name)
		}
		item := *it
		item, err = cwhub.DisableItem(csConfig.Cscli, item, purgeRemove)
		if err != nil {
			log.Fatalf("unable to disable %s : %v", item.Name, err)
		}
		cwhub.AddItemMap(ttype, item)
		return
	} else if name == "" && removeAll {
		for _, v := range cwhub.GetItemMap(ttype) {
			v, err = cwhub.DisableItem(csConfig.Cscli, v, purgeRemove)
			if err != nil {
				log.Fatalf("unable to disable %s : %v", v.Name, err)
			}
			cwhub.AddItemMap(ttype, v)
			disabled++
		}
	}
	if name != "" && !removeAll {
		log.Errorf("%s not found", name)
		return
	}
	log.Infof("Disabled %d items", disabled)
}

func UpgradeConfig(ttype string, name string) {
	var err error
	var updated int
	var found bool

	for _, v := range cwhub.GetItemMap(ttype) {
		//name mismatch
		if name != "" && name != v.Name {
			continue
		}
		if !v.Installed {
			log.Debugf("skip %s, not installed", v.Name)
			continue
		}
		if !v.Downloaded {
			log.Warningf("%s : not downloaded, please install.", v.Name)
			continue
		}
		found = true
		if v.UpToDate {
			log.Infof("%s : up-to-date", v.Name)
			continue
		}
		v, err = cwhub.DownloadLatest(csConfig.Cscli, v, forceUpgrade)
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
		cwhub.AddItemMap(ttype, v)
	}
	if !found {
		log.Errorf("Didn't find %s", name)
	} else if updated == 0 && found {
		log.Errorf("Nothing to update")
	} else if updated != 0 {
		log.Infof("Upgraded %d items", updated)
	}

}

func InspectItem(name string, objectType string) {

	hubItem := cwhub.GetItem(objectType, name)
	if hubItem == nil {
		log.Fatalf("unable to retrieve item.")
	}
	buff, err := yaml.Marshal(*hubItem)
	if err != nil {
		log.Fatalf("unable to marshal item : %s", err)
	}
	fmt.Printf("%s", string(buff))

}
