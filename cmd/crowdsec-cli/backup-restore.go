package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	log "github.com/sirupsen/logrus"
)

//it's a rip of the cli version, but in silent-mode
func silenceInstallItem(name string, obtype string) (string, error) {
	for _, it := range cwhub.GetItemMap(obtype) {
		if it.Name == name {
			if download_only && it.Downloaded && it.UpToDate {
				return fmt.Sprintf("%s is already downloaded and up-to-date", it.Name), nil
			}
			it, err := cwhub.DownloadLatest(it, cwhub.Hubdir, force_install, config.DataFolder)
			if err != nil {
				return "", fmt.Errorf("error while downloading %s : %v", it.Name, err)
			}
			cwhub.AddItemMap(obtype, it)

			if download_only {
				return fmt.Sprintf("Downloaded %s to %s", it.Name, cwhub.Hubdir+"/"+it.RemotePath), nil
			}
			it, err = cwhub.EnableItem(it, cwhub.Installdir, cwhub.Hubdir)
			if err != nil {
				return "", fmt.Errorf("error while enabled %s : %v", it.Name, err)
			}
			cwhub.AddItemMap(obtype, it)

			return fmt.Sprintf("Enabled %s", it.Name), nil
		}
	}
	return "", fmt.Errorf("%s not found in hub index", name)
}

/*help to copy the file, ioutil doesn't offer the feature*/

func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}

/*copy the file, ioutile doesn't offer the feature*/
func copyFile(sourceSymLink, destinationFile string) (err error) {

	sourceFile, err := filepath.EvalSymlinks(sourceSymLink)
	if err != nil {
		log.Infof("Not a symlink : %s", err)
		sourceFile = sourceSymLink
	}

	sourceFileStat, err := os.Stat(sourceFile)
	if err != nil {
		return
	}
	if !sourceFileStat.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories,
		// symlinks, devices, etc.)
		return fmt.Errorf("copyFile: non-regular source file %s (%q)", sourceFileStat.Name(), sourceFileStat.Mode().String())
	}
	destinationFileStat, err := os.Stat(destinationFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
	} else {
		if !(destinationFileStat.Mode().IsRegular()) {
			return fmt.Errorf("copyFile: non-regular destination file %s (%q)", destinationFileStat.Name(), destinationFileStat.Mode().String())
		}
		if os.SameFile(sourceFileStat, destinationFileStat) {
			return
		}
	}
	if err = os.Link(sourceFile, destinationFile); err == nil {
		return
	}
	err = copyFileContents(sourceFile, destinationFile)
	return
}
