package cwhub

// Install, upgrade and remove items from the hub to the local configuration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/enescakir/emoji"
	log "github.com/sirupsen/logrus"
)

// Upgrade downloads and applies the last version of the item from the hub.
func (i *Item) Upgrade(force bool) (bool, error) {
	updated := false

	if i.IsLocal() {
		log.Infof("not upgrading %s: local item", i.Name)
		return false, nil
	}

	if !i.State.Downloaded {
		return false, fmt.Errorf("can't upgrade %s: not installed", i.Name)
	}

	if !i.State.Installed {
		return false, fmt.Errorf("can't upgrade %s: downloaded but not installed", i.Name)
	}

	if i.State.UpToDate {
		log.Infof("%s: up-to-date", i.Name)

		if err := i.DownloadDataIfNeeded(force); err != nil {
			return false, fmt.Errorf("%s: download failed: %w", i.Name, err)
		}

		if !force {
			// no upgrade needed
			return false, nil
		}
	}

	if _, err := i.downloadLatest(force, true); err != nil {
		return false, fmt.Errorf("%s: download failed: %w", i.Name, err)
	}

	if !i.State.UpToDate {
		if i.State.Tainted {
			log.Warningf("%v %s is tainted, --force to overwrite", emoji.Warning, i.Name)
		}
	} else {
		// a check on stdout is used while scripting to know if the hub has been upgraded
		// and a configuration reload is required
		// TODO: use a better way to communicate this
		fmt.Printf("updated %s\n", i.Name)
		log.Infof("%v %s: updated", emoji.Package, i.Name)
		updated = true
	}

	return updated, nil
}

// downloadLatest downloads the latest version of the item to the hub directory.
func (i *Item) downloadLatest(overwrite bool, updateOnly bool) (string, error) {
	log.Debugf("Downloading %s %s", i.Type, i.Name)

	for _, sub := range i.SubItems() {
		if !sub.State.Installed && updateOnly && sub.State.Downloaded {
			log.Debugf("skipping upgrade of %s: not installed", i.Name)
			continue
		}

		log.Debugf("Download %s sub-item: %s %s (%t -> %t)", i.Name, sub.Type, sub.Name, i.State.Installed, updateOnly)

		// recurse as it's a collection
		if sub.HasSubItems() {
			log.Tracef("collection, recurse")

			if _, err := sub.downloadLatest(overwrite, updateOnly); err != nil {
				return "", fmt.Errorf("while downloading %s: %w", sub.Name, err)
			}
		}

		downloaded := sub.State.Downloaded

		if _, err := sub.download(overwrite); err != nil {
			return "", fmt.Errorf("while downloading %s: %w", sub.Name, err)
		}

		// We need to enable an item when it has been added to a collection since latest release of the collection.
		// We check if sub.Downloaded is false because maybe the item has been disabled by the user.
		if !sub.State.Installed && !downloaded {
			if err := sub.enable(); err != nil {
				return "", fmt.Errorf("enabling '%s': %w", sub.Name, err)
			}
		}
	}

	if !i.State.Installed && updateOnly && i.State.Downloaded {
		log.Debugf("skipping upgrade of %s: not installed", i.Name)
		return "", nil
	}

	ret, err := i.download(overwrite)
	if err != nil {
		return "", fmt.Errorf("failed to download item: %w", err)
	}

	return ret, nil
}

// fetch downloads the item from the hub, verifies the hash and returns the content.
func (i *Item) fetch() ([]byte, error) {
	url, err := i.hub.remote.urlTo(i.RemotePath)
	if err != nil {
		return nil, fmt.Errorf("failed to build hub item request: %w", err)
	}

	resp, err := hubClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("while downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad http code %d for %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("while downloading %s: %w", url, err)
	}

	hash := sha256.New()
	if _, err = hash.Write(body); err != nil {
		return nil, fmt.Errorf("while hashing %s: %w", i.Name, err)
	}

	meow := hex.EncodeToString(hash.Sum(nil))
	if meow != i.Versions[i.Version].Digest {
		log.Errorf("Downloaded version doesn't match index, please 'hub update'")
		log.Debugf("got %s, expected %s", meow, i.Versions[i.Version].Digest)

		return nil, fmt.Errorf("invalid download hash for %s", i.Name)
	}

	return body, nil
}

// download downloads the item from the hub and writes it to the hub directory.
func (i *Item) download(overwrite bool) (string, error) {
	if i.IsLocal() {
		return "", fmt.Errorf("%s is local, can't download", i.Name)
	}
	// if user didn't --force, don't overwrite local, tainted, up-to-date files
	if !overwrite {
		if i.State.Tainted {
			log.Debugf("%s: tainted, not updated", i.Name)
			return "", nil
		}

		if i.State.UpToDate {
			//  We still have to check if data files are present
			log.Debugf("%s: up-to-date, not updated", i.Name)
		}
	}

	body, err := i.fetch()
	if err != nil {
		return "", err
	}

	// all good, install

	// ensure that target file is within target dir
	finalPath, err := i.downloadPath()
	if err != nil {
		return "", err
	}

	parentDir := filepath.Dir(finalPath)

	if err = os.MkdirAll(parentDir, os.ModePerm); err != nil {
		return "", fmt.Errorf("while creating %s: %w", parentDir, err)
	}

	// check actual file
	if _, err = os.Stat(finalPath); !os.IsNotExist(err) {
		log.Warningf("%s: overwrite", i.Name)
		log.Debugf("target: %s", finalPath)
	} else {
		log.Infof("%s: OK", i.Name)
	}

	if err = os.WriteFile(finalPath, body, 0o644); err != nil {
		return "", fmt.Errorf("while writing %s: %w", finalPath, err)
	}

	i.State.Downloaded = true
	i.State.Tainted = false
	i.State.UpToDate = true

	if err = downloadDataSet(i.hub.local.InstallDataDir, overwrite, bytes.NewReader(body)); err != nil {
		return "", fmt.Errorf("while downloading data for %s: %w", i.FileName, err)
	}

	return finalPath, nil
}

// DownloadDataIfNeeded downloads the data set for the item.
func (i *Item) DownloadDataIfNeeded(force bool) error {
	itemFilePath, err := i.installPath()
	if err != nil {
		return err
	}

	itemFile, err := os.Open(itemFilePath)
	if err != nil {
		return fmt.Errorf("while opening %s: %w", itemFilePath, err)
	}

	defer itemFile.Close()

	if err = downloadDataSet(i.hub.local.InstallDataDir, force, itemFile); err != nil {
		return fmt.Errorf("while downloading data for %s: %w", itemFilePath, err)
	}

	return nil
}
