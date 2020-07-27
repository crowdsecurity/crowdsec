package cwhub

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

//DisableItem to disable an item managed by the hub, removes the symlink if purge is true
func DisableItem(target Item, tdir string, hdir string, purge bool) (Item, error) {
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
					HubIdx[ptrtype][p], err = DisableItem(val, Installdir, Hubdir, false)
					if err != nil {
						log.Errorf("Encountered error while disabling %s %s : %s.", ptrtype, p, err)
					}
				} else {
					log.Errorf("Referred %s %s in collection %s doesn't exist.", ptrtype, p, target.Name)
				}
			}
		}

	}

	stat, err := os.Lstat(syml)
	if os.IsNotExist(err) {
		log.Warningf("%s (%s) doesn't exist, can't disable", target.Name, syml)
		//return target, nil //fmt.Errorf("'%s' doesn't exist", syml)
	} else {
		//if it's managed by hub, it's a symlink to Hubdir / ...
		if stat.Mode()&os.ModeSymlink == 0 {
			log.Warningf("%s (%s) isn't a symlink, can't disable", target.Name, syml)
			return target, fmt.Errorf("%s isn't managed by hub", target.Name)
		}
		hubpath, err := os.Readlink(syml)
		if err != nil {
			return target, fmt.Errorf("unable to read symlink of %s (%s)", target.Name, syml)
		}
		absPath, err := filepath.Abs(hdir + "/" + target.RemotePath)
		if err != nil {
			return target, err
		}
		if hubpath != absPath {
			log.Warningf("%s (%s) isn't a symlink to %s", target.Name, syml, absPath)
			return target, fmt.Errorf("%s isn't managed by hub", target.Name)
		}

		//remove the symlink
		if err = os.Remove(syml); err != nil {
			return target, fmt.Errorf("failed to unlink %s: %+v", syml, err)
		}
		log.Infof("Removed symlink [%s] : %s", target.Name, syml)
	}
	target.Installed = false

	if purge {
		hubpath := hdir + "/" + target.RemotePath
		//if purge, disable hub file
		if err = os.Remove(hubpath); err != nil {
			return target, fmt.Errorf("failed to purge hub file %s: %+v", hubpath, err)
		}
		target.Downloaded = false
		log.Infof("Removed source file [%s] : %s", target.Name, hubpath)
	}
	HubIdx[target.Type][target.Name] = target
	return target, nil
}

func EnableItem(target Item, tdir string, hdir string) (Item, error) {
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
			log.Debugf("%s is installed and up-to-date, skip.", target.Name)
			return target, nil
		}
	}
	if _, err := os.Stat(parent_dir); os.IsNotExist(err) {
		log.Printf("%s doesn't exist, create", parent_dir)
		if err := os.MkdirAll(parent_dir, os.ModePerm); err != nil {
			return target, fmt.Errorf("unable to create parent directories")
		}
	}

	/*install sub-items if it's a collection*/
	if target.Type == COLLECTIONS {
		var tmp = [][]string{target.Parsers, target.PostOverflows, target.Scenarios, target.Collections}
		for idx, ptr := range tmp {
			ptrtype := ItemTypes[idx]
			for _, p := range ptr {
				if val, ok := HubIdx[ptrtype][p]; ok {
					HubIdx[ptrtype][p], err = EnableItem(val, Installdir, Hubdir)
					if err != nil {
						log.Errorf("Encountered error while installing sub-item %s %s : %s.", ptrtype, p, err)
						return target, fmt.Errorf("encountered error while install %s for %s, abort.", val.Name, target.Name)
					}
				} else {
					//log.Errorf("Referred %s %s in collection %s doesn't exist.", ptrtype, p, target.Name)
					return target, fmt.Errorf("required %s %s of %s doesn't exist, abort.", ptrtype, p, target.Name)
				}
			}
		}
	}

	if _, err := os.Lstat(parent_dir + "/" + target.FileName); os.IsNotExist(err) {
		//tdir+target.RemotePath
		srcPath, err := filepath.Abs(hdir + "/" + target.RemotePath)
		if err != nil {
			return target, fmt.Errorf("failed to resolve %s : %s", hdir+"/"+target.RemotePath, err)
		}
		dstPath, err := filepath.Abs(parent_dir + "/" + target.FileName)
		if err != nil {
			return target, fmt.Errorf("failed to resolve %s : %s", parent_dir+"/"+target.FileName, err)
		}
		err = os.Symlink(srcPath, dstPath)
		if err != nil {
			log.Fatalf("Failed to symlink %s to %s : %v", srcPath, dstPath, err)
			return target, fmt.Errorf("failed to symlink %s to %s", srcPath, dstPath)
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
