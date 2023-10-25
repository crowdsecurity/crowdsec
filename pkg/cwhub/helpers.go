package cwhub

// Install, upgrade and remove items from the hub to the local configuration

// XXX: this file could use a better name

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/enescakir/emoji"
	log "github.com/sirupsen/logrus"
)

// InstallItem installs an item from the hub
func (h *Hub) InstallItem(name string, itemType string, force bool, downloadOnly bool, hubURLTemplate, branch string) error {
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

	err := h.DownloadLatest(item, force, true, hubURLTemplate, branch)
	if err != nil {
		return fmt.Errorf("while downloading %s: %w", item.Name, err)
	}

	if err = h.AddItem(*item); err != nil {
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

	if err := h.AddItem(*item); err != nil {
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

		if err = h.AddItem(*item); err != nil {
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

		if err := h.AddItem(v); err != nil {
			return fmt.Errorf("unable to add %s: %w", v.Name, err)
		}
		disabled++
	}

	log.Infof("Disabled %d items", disabled)

	return nil
}

// UpgradeConfig upgrades an item from the hub
func (h *Hub) UpgradeConfig(itemType string, name string, force bool, hubURLTemplate, branch string) error {
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

		if err := h.DownloadLatest(&v, force, true, hubURLTemplate, branch); err != nil {
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

		if err := h.AddItem(v); err != nil {
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

// DownloadLatest will download the latest version of Item to the tdir directory
func (h *Hub) DownloadLatest(target *Item, overwrite bool, updateOnly bool, hubURLTemplate, branch string) error {
	var err error

	log.Debugf("Downloading %s %s", target.Type, target.Name)

	if target.Type != COLLECTIONS {
		if !target.Installed && updateOnly && target.Downloaded {
			log.Debugf("skipping upgrade of %s : not installed", target.Name)
			return nil
		}

		return h.DownloadItem(target, overwrite, hubURLTemplate, branch)
	}

	// collection
	for _, sub := range target.SubItems() {
		val, ok := h.Items[sub.Type][sub.Name]
		if !ok {
			return fmt.Errorf("required %s %s of %s doesn't exist, abort", sub.Type, sub.Name, target.Name)
		}

		if !val.Installed && updateOnly && val.Downloaded {
			log.Debugf("skipping upgrade of %s : not installed", target.Name)
			continue
		}

		log.Debugf("Download %s sub-item : %s %s (%t -> %t)", target.Name, sub.Type, sub.Name, target.Installed, updateOnly)
		//recurse as it's a collection
		if sub.Type == COLLECTIONS {
			log.Tracef("collection, recurse")

			err = h.DownloadLatest(&val, overwrite, updateOnly, hubURLTemplate, branch)
			if err != nil {
				return fmt.Errorf("while downloading %s: %w", val.Name, err)
			}
		}

		downloaded := val.Downloaded

		err = h.DownloadItem(&val, overwrite, hubURLTemplate, branch)
		if err != nil {
			return fmt.Errorf("while downloading %s: %w", val.Name, err)
		}

		// We need to enable an item when it has been added to a collection since latest release of the collection.
		// We check if val.Downloaded is false because maybe the item has been disabled by the user.
		if !val.Installed && !downloaded {
			if err = h.EnableItem(&val); err != nil {
				return fmt.Errorf("enabling '%s': %w", val.Name, err)
			}
		}

		h.Items[sub.Type][sub.Name] = val
	}

	err = h.DownloadItem(target, overwrite, hubURLTemplate, branch)
	if err != nil {
		return fmt.Errorf("failed to download item: %w", err)
	}

	return nil
}

func (h *Hub) DownloadItem(target *Item, overwrite bool, hubURLTemplate, branch string) error {
	url := fmt.Sprintf(hubURLTemplate, branch, target.RemotePath)
	tdir := h.cfg.HubDir

	// if user didn't --force, don't overwrite local, tainted, up-to-date files
	if !overwrite {
		if target.Tainted {
			log.Debugf("%s : tainted, not updated", target.Name)
			return nil
		}

		if target.UpToDate {
			//  We still have to check if data files are present
			log.Debugf("%s : up-to-date, not updated", target.Name)
		}
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("while downloading %s: %w", req.URL.String(), err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("while downloading %s: %w", req.URL.String(), err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad http code %d for %s", resp.StatusCode, req.URL.String())
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("while reading %s: %w", req.URL.String(), err)
	}

	hash := sha256.New()
	if _, err = hash.Write(body); err != nil {
		return fmt.Errorf("while hashing %s: %w", target.Name, err)
	}

	meow := hex.EncodeToString(hash.Sum(nil))
	if meow != target.Versions[target.Version].Digest {
		log.Errorf("Downloaded version doesn't match index, please 'hub update'")
		log.Debugf("got %s, expected %s", meow, target.Versions[target.Version].Digest)

		return fmt.Errorf("invalid download hash for %s", target.Name)
	}

	//all good, install
	//check if parent dir exists
	tmpdirs := strings.Split(tdir+"/"+target.RemotePath, "/")
	parentDir := strings.Join(tmpdirs[:len(tmpdirs)-1], "/")

	// ensure that target file is within target dir
	finalPath, err := filepath.Abs(tdir + "/" + target.RemotePath)
	if err != nil {
		return fmt.Errorf("filepath.Abs error on %s: %w", tdir+"/"+target.RemotePath, err)
	}

	if !strings.HasPrefix(finalPath, tdir) {
		return fmt.Errorf("path %s escapes %s, abort", target.RemotePath, tdir)
	}

	// check dir
	if _, err = os.Stat(parentDir); os.IsNotExist(err) {
		log.Debugf("%s doesn't exist, create", parentDir)

		if err = os.MkdirAll(parentDir, os.ModePerm); err != nil {
			return fmt.Errorf("while creating parent directories: %w", err)
		}
	}

	// check actual file
	if _, err = os.Stat(finalPath); !os.IsNotExist(err) {
		log.Warningf("%s : overwrite", target.Name)
		log.Debugf("target: %s/%s", tdir, target.RemotePath)
	} else {
		log.Infof("%s : OK", target.Name)
	}

	f, err := os.OpenFile(tdir+"/"+target.RemotePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("while opening file: %w", err)
	}

	defer f.Close()

	_, err = f.Write(body)
	if err != nil {
		return fmt.Errorf("while writing file: %w", err)
	}

	target.Downloaded = true
	target.Tainted = false
	target.UpToDate = true

	if err = downloadData(h.cfg.InstallDataDir, overwrite, bytes.NewReader(body)); err != nil {
		return fmt.Errorf("while downloading data for %s: %w", target.FileName, err)
	}

	h.Items[target.Type][target.Name] = *target

	return nil
}

// DownloadDataIfNeeded downloads the data files for an item
func (h *Hub) DownloadDataIfNeeded(target Item, force bool) error {
	itemFilePath := fmt.Sprintf("%s/%s/%s/%s", h.cfg.InstallDir, target.Type, target.Stage, target.FileName)

	itemFile, err := os.Open(itemFilePath)
	if err != nil {
		return fmt.Errorf("while opening %s: %w", itemFilePath, err)
	}

	defer itemFile.Close()

	if err = downloadData(h.cfg.InstallDataDir, force, itemFile); err != nil {
		return fmt.Errorf("while downloading data for %s: %w", itemFilePath, err)
	}

	return nil
}
