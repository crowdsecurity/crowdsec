package cwhub

// Install, upgrade and remove items from the hub to the local configuration

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/downloader"

	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

// Upgrade downloads and applies the last version of the item from the hub.
func (i *Item) Upgrade(ctx context.Context, force bool) (bool, error) {
	if i.State.IsLocal() {
		i.hub.logger.Infof("not upgrading %s: local item", i.Name)
		return false, nil
	}

	if !i.State.Downloaded {
		return false, fmt.Errorf("can't upgrade %s: not installed", i.Name)
	}

	if !i.State.Installed {
		return false, fmt.Errorf("can't upgrade %s: downloaded but not installed", i.Name)
	}

	if i.State.UpToDate {
		i.hub.logger.Infof("%s: up-to-date", i.Name)

		if err := i.DownloadDataIfNeeded(ctx, force); err != nil {
			return false, fmt.Errorf("%s: download failed: %w", i.Name, err)
		}

		if !force {
			// no upgrade needed
			return false, nil
		}
	}

	if _, err := i.downloadLatest(ctx, force, true); err != nil {
		return false, fmt.Errorf("%s: download failed: %w", i.Name, err)
	}

	if !i.State.UpToDate {
		if i.State.Tainted {
			i.hub.logger.Warningf("%v %s is tainted, --force to overwrite", emoji.Warning, i.Name)
		}

		return false, nil
	}

	// a check on stdout is used while scripting to know if the hub has been upgraded
	// and a configuration reload is required
	// TODO: use a better way to communicate this
	fmt.Printf("updated %s\n", i.Name)
	i.hub.logger.Infof("%v %s: updated", emoji.Package, i.Name)

	return true, nil
}

// downloadLatest downloads the latest version of the item to the hub directory.
func (i *Item) downloadLatest(ctx context.Context, overwrite bool, updateOnly bool) (bool, error) {
	i.hub.logger.Debugf("Downloading %s %s", i.Type, i.Name)

	for _, sub := range i.SubItems() {
		if !sub.State.Installed && updateOnly && sub.State.Downloaded {
			i.hub.logger.Debugf("skipping upgrade of %s: not installed", i.Name)
			continue
		}

		i.hub.logger.Debugf("Download %s sub-item: %s %s (%t -> %t)", i.Name, sub.Type, sub.Name, i.State.Installed, updateOnly)

		// recurse as it's a collection
		if sub.HasSubItems() {
			i.hub.logger.Tracef("collection, recurse")

			if _, err := sub.downloadLatest(ctx, overwrite, updateOnly); err != nil {
				return false, err
			}
		}

		downloaded := sub.State.Downloaded

		if _, err := sub.download(ctx, overwrite); err != nil {
			return false, err
		}

		// We need to enable an item when it has been added to a collection since latest release of the collection.
		// We check if sub.Downloaded is false because maybe the item has been disabled by the user.
		if !sub.State.Installed && !downloaded {
			if err := sub.enable(); err != nil {
				return false, fmt.Errorf("enabling '%s': %w", sub.Name, err)
			}
		}
	}

	if !i.State.Installed && updateOnly && i.State.Downloaded && !overwrite {
		i.hub.logger.Debugf("skipping upgrade of %s: not installed", i.Name)
		return false, nil
	}

	return i.download(ctx, overwrite)
}

// FetchContentTo downloads the last version of the item's YAML file to the specified path.
func (i *Item) FetchContentTo(ctx context.Context, destPath string) (bool, string, error) {
	url, err := i.hub.remote.urlTo(i.RemotePath)
	if err != nil {
		return false, "", fmt.Errorf("failed to build request: %w", err)
	}

	wantHash := i.latestHash()
	if wantHash == "" {
		return false, "", errors.New("latest hash missing from index")
	}

	d := downloader.
		New().
		WithHTTPClient(hubClient).
		ToFile(destPath).
		WithMakeDirs(true).
		WithLogger(logrus.WithFields(logrus.Fields{"url": url})).
		CompareContent().
		VerifyHash("sha256", wantHash)

	// TODO: recommend hub update if hash does not match

	downloaded, err := d.Download(ctx, url)
	if err != nil {
		return false, "", fmt.Errorf("while downloading %s to %s: %w", i.Name, url, err)
	}

	return downloaded, url, nil
}

// download downloads the item from the hub and writes it to the hub directory.
func (i *Item) download(ctx context.Context, overwrite bool) (bool, error) {
	// ensure that target file is within target dir
	finalPath, err := i.downloadPath()
	if err != nil {
		return false, err
	}

	if i.State.IsLocal() {
		i.hub.logger.Warningf("%s is local, can't download", i.Name)
		return false, nil
	}

	// if user didn't --force, don't overwrite local, tainted, up-to-date files
	if !overwrite {
		if i.State.Tainted {
			i.hub.logger.Debugf("%s: tainted, not updated", i.Name)
			return false, nil
		}

		if i.State.UpToDate {
			//  We still have to check if data files are present
			i.hub.logger.Debugf("%s: up-to-date, not updated", i.Name)
		}
	}

	downloaded, _, err := i.FetchContentTo(ctx, finalPath)
	if err != nil {
		return false, fmt.Errorf("while downloading %s: %w", i.Name, err)
	}

	if downloaded {
		i.hub.logger.Infof("Downloaded %s", i.Name)
	}

	i.State.Downloaded = true
	i.State.Tainted = false
	i.State.UpToDate = true

	// read content to get the list of data files
	reader, err := os.Open(finalPath)
	if err != nil {
		return false, fmt.Errorf("while opening %s: %w", finalPath, err)
	}

	defer reader.Close()

	if err = downloadDataSet(ctx, i.hub.local.InstallDataDir, overwrite, reader, i.hub.logger); err != nil {
		return false, fmt.Errorf("while downloading data for %s: %w", i.FileName, err)
	}

	return true, nil
}

// DownloadDataIfNeeded downloads the data set for the item.
func (i *Item) DownloadDataIfNeeded(ctx context.Context, force bool) error {
	itemFilePath, err := i.installPath()
	if err != nil {
		return err
	}

	itemFile, err := os.Open(itemFilePath)
	if err != nil {
		return fmt.Errorf("while opening %s: %w", itemFilePath, err)
	}

	defer itemFile.Close()

	if err = downloadDataSet(ctx, i.hub.local.InstallDataDir, force, itemFile, i.hub.logger); err != nil {
		return fmt.Errorf("while downloading data for %s: %w", itemFilePath, err)
	}

	return nil
}
