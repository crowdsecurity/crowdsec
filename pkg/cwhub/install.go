package cwhub

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

//DisableItem to disable an item managed by the hub, removes the symlink if purge is true
func DisableItem(cscli *csconfig.CscliCfg, target Item, purge bool) (Item, error) {
	var tdir = cscli.ConfigDir
	var hdir = cscli.HubDir

	syml, err := filepath.Abs(tdir + "/" + target.Type + "/" + target.Stage + "/" + target.FileName)
	if err != nil {
		return Item{}, err
	}
	if target.Local {
		return target, fmt.Errorf("%s isn't managed by hub. Please delete manually", target.Name)
	}

	/*for a COLLECTIONS, disable sub-items*/
	if target.Type == COLLECTIONS {
		var tmp = [][]string{target.Parsers, target.PostOverflows, target.Scenarios, target.Collections}
		for idx, ptr := range tmp {
			ptrtype := ItemTypes[idx]
			for _, p := range ptr {
				if val, ok := HubIdx[ptrtype][p]; ok {
					HubIdx[ptrtype][p], err = DisableItem(cscli, val, purge)
					if err != nil {
						return target, errors.Wrap(err, fmt.Sprintf("while disabling %s", p))
					}
				} else {
					log.Errorf("Referred %s %s in collection %s doesn't exist.", ptrtype, p, target.Name)
				}
			}
		}

	}

	stat, err := os.Lstat(syml)
	if os.IsNotExist(err) {
		if !purge { //we only accept to "delete" non existing items if it's a purge
			return target, fmt.Errorf("can't delete %s : %s doesn't exist", target.Name, syml)
		}
	} else {
		//if it's managed by hub, it's a symlink to csconfig.GConfig.Cscli.HubDir / ...
		if stat.Mode()&os.ModeSymlink == 0 {
			log.Warningf("%s (%s) isn't a symlink, can't disable", target.Name, syml)
			return target, fmt.Errorf("%s isn't managed by hub", target.Name)
		}
		hubpath, err := os.Readlink(syml)
		if err != nil {
			return target, errors.Wrap(err, "while reading symlink")
		}
		absPath, err := filepath.Abs(hdir + "/" + target.RemotePath)
		if err != nil {
			return target, errors.Wrap(err, "while abs path")
		}
		if hubpath != absPath {
			log.Warningf("%s (%s) isn't a symlink to %s", target.Name, syml, absPath)
			return target, fmt.Errorf("%s isn't managed by hub", target.Name)
		}

		//remove the symlink
		if err = os.Remove(syml); err != nil {
			return target, errors.Wrap(err, "while removing symlink")
		}
		log.Infof("Removed symlink [%s] : %s", target.Name, syml)
	}
	target.Installed = false

	if purge {
		hubpath := hdir + "/" + target.RemotePath
		//if purge, disable hub file
		if err = os.Remove(hubpath); err != nil {
			return target, errors.Wrap(err, "while removing file")
		}
		target.Downloaded = false
		log.Infof("Removed source file [%s] : %s", target.Name, hubpath)
	}
	HubIdx[target.Type][target.Name] = target
	return target, nil
}

func EnableItem(cscli *csconfig.CscliCfg, target Item) (Item, error) {
	var tdir = cscli.ConfigDir
	var hdir = cscli.HubDir
	var err error
	parent_dir := filepath.Clean(tdir + "/" + target.Type + "/" + target.Stage + "/")
	/*create directories if needed*/
	if target.Installed {
		if target.Tainted {
			return target, fmt.Errorf("%s is tainted, won't enable unless --force", target.Name)
		}
		if target.Local {
			return target, fmt.Errorf("%s is local, won't enable", target.Name)
		}
		/* if it's a collection, check sub-items even if the collection file itself is up-to-date */
		if target.UpToDate && target.Type != COLLECTIONS {
			log.Tracef("%s is installed and up-to-date, skip.", target.Name)
			return target, nil
		}
	}
	if _, err := os.Stat(parent_dir); os.IsNotExist(err) {
		log.Printf("%s doesn't exist, create", parent_dir)
		if err := os.MkdirAll(parent_dir, os.ModePerm); err != nil {
			return target, errors.Wrap(err, "while creating directory")
		}
	}

	/*install sub-items if it's a collection*/
	if target.Type == COLLECTIONS {
		var tmp = [][]string{target.Parsers, target.PostOverflows, target.Scenarios, target.Collections}
		for idx, ptr := range tmp {
			ptrtype := ItemTypes[idx]
			for _, p := range ptr {
				if val, ok := HubIdx[ptrtype][p]; ok {
					HubIdx[ptrtype][p], err = EnableItem(cscli, val)
					if err != nil {
						return target, errors.Wrap(err, fmt.Sprintf("while installing %s", p))
					}
				} else {
					return target, fmt.Errorf("required %s %s of %s doesn't exist, abort.", ptrtype, p, target.Name)
				}
			}
		}
	}

	if _, err := os.Lstat(parent_dir + "/" + target.FileName); os.IsNotExist(err) {
		//tdir+target.RemotePath
		srcPath, err := filepath.Abs(hdir + "/" + target.RemotePath)
		if err != nil {
			return target, errors.Wrap(err, "while getting source path")
		}
		dstPath, err := filepath.Abs(parent_dir + "/" + target.FileName)
		if err != nil {
			return target, errors.Wrap(err, "while getting destination path")
		}
		err = os.Symlink(srcPath, dstPath)
		if err != nil {
			return target, errors.Wrap(err, fmt.Sprintf("while creating symlink from %s to %s", srcPath, dstPath))
		}
		log.Printf("Enabled %s : %s", target.Type, target.Name)
	} else {
		log.Printf("%s already exists.", parent_dir+"/"+target.FileName)
		return target, nil
	}
	target.Installed = true
	HubIdx[target.Type][target.Name] = target
	return target, nil
}
