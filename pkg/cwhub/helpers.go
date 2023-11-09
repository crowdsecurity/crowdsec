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

// Install installs an item from the hub, downloading it if needed
func (i *Item) Install(force bool, downloadOnly bool) error {
	if downloadOnly && i.Downloaded && i.UpToDate {
		log.Warningf("%s is already downloaded and up-to-date", i.Name)

		if !force {
			return nil
		}
	}

	// XXX: confusing semantic between force and updateOnly?
	if err := i.downloadLatest(force, true); err != nil {
		return fmt.Errorf("while downloading %s: %w", i.Name, err)
	}

	if err := i.hub.AddItem(*i); err != nil {
		return fmt.Errorf("while adding %s: %w", i.Name, err)
	}

	if downloadOnly {
		// XXX: should get the path from downloadLatest
		log.Infof("Downloaded %s to %s", i.Name, filepath.Join(i.hub.local.HubDir, i.RemotePath))
		return nil
	}

	// XXX: should we stop here if the item is already installed?

	if err := i.enable(); err != nil {
		return fmt.Errorf("while enabling %s: %w", i.Name, err)
	}

	if err := i.hub.AddItem(*i); err != nil {
		return fmt.Errorf("while adding %s: %w", i.Name, err)
	}

	log.Infof("Enabled %s", i.Name)

	return nil
}

// Remove disables the item, optionally removing the downloaded content
func (i *Item) Remove(purge bool, forceAction bool) (bool, error) {
	removed := false

	if !i.Downloaded {
		log.Infof("removing %s: not downloaded -- no removal required", i.Name)
		return false, nil
	}

	if !i.Installed && !purge {
		log.Infof("removing %s: already uninstalled", i.Name)
		return false, nil
	}

	if err := i.disable(purge, forceAction); err != nil {
		return false, fmt.Errorf("unable to disable %s: %w", i.Name, err)
	}

	// XXX: should take the value from disable()
	removed = true

	if err := i.hub.AddItem(*i); err != nil {
		return false, fmt.Errorf("unable to refresh item state %s: %w", i.Name, err)
	}

	return removed, nil
}

// UpgradeItem upgrades an item from the hub
func (h *Hub) UpgradeItem(itemType string, name string, force bool) (bool, error) {
	updated := false

	item := h.GetItem(itemType, name)
	if item == nil {
		return false, fmt.Errorf("can't find '%s' in %s", name, itemType)
	}

	if !item.Downloaded {
		return false, fmt.Errorf("can't upgrade %s: not installed", item.Name)
	}

	if !item.Installed {
		return false, fmt.Errorf("can't upgrade %s: downloaded but not installed", item.Name)
	}

	if item.UpToDate {
		log.Infof("%s: up-to-date", item.Name)

		if err := item.DownloadDataIfNeeded(force); err != nil {
			return false, fmt.Errorf("%s: download failed: %w", item.Name, err)
		}

		if !force {
			// no upgrade needed
			return false, nil
		}
	}

	if err := item.downloadLatest(force, true); err != nil {
		return false, fmt.Errorf("%s: download failed: %w", item.Name, err)
	}

	if !item.UpToDate {
		if item.Tainted {
			log.Infof("%v %s is tainted, --force to overwrite", emoji.Warning, item.Name)
		} else if item.IsLocal() {
			log.Infof("%v %s is local", emoji.Prohibited, item.Name)
		}
	} else {
		// a check on stdout is used while scripting to know if the hub has been upgraded
		// and a configuration reload is required
		// TODO: use a better way to communicate this
		fmt.Printf("updated %s\n", item.Name)
		log.Infof("%v %s: updated", emoji.Package, item.Name)
		updated = true
	}

	if err := h.AddItem(*item); err != nil {
		return false, fmt.Errorf("unable to refresh item state %s: %w", item.Name, err)
	}

	return updated, nil
}

// downloadLatest will download the latest version of Item to the tdir directory
func (i *Item) downloadLatest(overwrite bool, updateOnly bool) error {
	// XXX: should return the path of the downloaded file (taken from download())
	log.Debugf("Downloading %s %s", i.Type, i.Name)

	if !i.HasSubItems() {
		if !i.Installed && updateOnly && i.Downloaded {
			log.Debugf("skipping upgrade of %s: not installed", i.Name)
			return nil
		}

		// XXX:
		return i.download(overwrite)
	}

	// collection
	for _, sub := range i.SubItems() {
		val, ok := i.hub.Items[sub.Type][sub.Name]
		if !ok {
			return fmt.Errorf("required %s %s of %s doesn't exist, abort", sub.Type, sub.Name, i.Name)
		}

		if !val.Installed && updateOnly && val.Downloaded {
			log.Debugf("skipping upgrade of %s: not installed", i.Name)
			continue
		}

		log.Debugf("Download %s sub-item: %s %s (%t -> %t)", i.Name, sub.Type, sub.Name, i.Installed, updateOnly)

		// recurse as it's a collection
		if sub.HasSubItems() {
			log.Tracef("collection, recurse")

			if err := val.downloadLatest(overwrite, updateOnly); err != nil {
				return fmt.Errorf("while downloading %s: %w", val.Name, err)
			}
		}

		downloaded := val.Downloaded

		if err := val.download(overwrite); err != nil {
			return fmt.Errorf("while downloading %s: %w", val.Name, err)
		}

		// We need to enable an item when it has been added to a collection since latest release of the collection.
		// We check if val.Downloaded is false because maybe the item has been disabled by the user.
		if !val.Installed && !downloaded {
			if err := val.enable(); err != nil {
				return fmt.Errorf("enabling '%s': %w", val.Name, err)
			}
		}

		i.hub.Items[sub.Type][sub.Name] = val
	}

	if err := i.download(overwrite); err != nil {
		return fmt.Errorf("failed to download item: %w", err)
	}

	return nil
}

func (i *Item) download(overwrite bool) error {
	url, err := i.hub.remote.urlTo(i.RemotePath)
	if err != nil {
		return fmt.Errorf("failed to build hub item request: %w", err)
	}

	tdir := i.hub.local.HubDir

	// if user didn't --force, don't overwrite local, tainted, up-to-date files
	if !overwrite {
		if i.Tainted {
			log.Debugf("%s: tainted, not updated", i.Name)
			return nil
		}

		if i.UpToDate {
			//  We still have to check if data files are present
			log.Debugf("%s: up-to-date, not updated", i.Name)
		}
	}

	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return fmt.Errorf("while downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad http code %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("while downloading %s: %w", url, err)
	}

	hash := sha256.New()
	if _, err = hash.Write(body); err != nil {
		return fmt.Errorf("while hashing %s: %w", i.Name, err)
	}

	meow := hex.EncodeToString(hash.Sum(nil))
	if meow != i.Versions[i.Version].Digest {
		log.Errorf("Downloaded version doesn't match index, please 'hub update'")
		log.Debugf("got %s, expected %s", meow, i.Versions[i.Version].Digest)

		return fmt.Errorf("invalid download hash for %s", i.Name)
	}

	//all good, install
	//check if parent dir exists
	tmpdirs := strings.Split(tdir+"/"+i.RemotePath, "/")
	parentDir := strings.Join(tmpdirs[:len(tmpdirs)-1], "/")

	// ensure that target file is within target dir
	finalPath, err := filepath.Abs(tdir + "/" + i.RemotePath)
	if err != nil {
		return fmt.Errorf("filepath.Abs error on %s: %w", tdir+"/"+i.RemotePath, err)
	}

	if !strings.HasPrefix(finalPath, tdir) {
		return fmt.Errorf("path %s escapes %s, abort", i.RemotePath, tdir)
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
		log.Warningf("%s: overwrite", i.Name)
		log.Debugf("target: %s/%s", tdir, i.RemotePath)
	} else {
		log.Infof("%s: OK", i.Name)
	}

	f, err := os.OpenFile(tdir+"/"+i.RemotePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("while opening file: %w", err)
	}

	defer f.Close()

	_, err = f.Write(body)
	if err != nil {
		return fmt.Errorf("while writing file: %w", err)
	}

	i.Downloaded = true
	i.Tainted = false
	i.UpToDate = true

	if err = downloadData(i.hub.local.InstallDataDir, overwrite, bytes.NewReader(body)); err != nil {
		return fmt.Errorf("while downloading data for %s: %w", i.FileName, err)
	}

	i.hub.Items[i.Type][i.Name] = *i

	return nil
}

// DownloadDataIfNeeded downloads the data files for an item
func (i *Item) DownloadDataIfNeeded(force bool) error {
	itemFilePath := fmt.Sprintf("%s/%s/%s/%s", i.hub.local.InstallDir, i.Type, i.Stage, i.FileName)

	itemFile, err := os.Open(itemFilePath)
	if err != nil {
		return fmt.Errorf("while opening %s: %w", itemFilePath, err)
	}

	defer itemFile.Close()

	if err = downloadData(i.hub.local.InstallDataDir, force, itemFile); err != nil {
		return fmt.Errorf("while downloading data for %s: %w", itemFilePath, err)
	}

	return nil
}
