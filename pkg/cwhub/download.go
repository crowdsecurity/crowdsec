package cwhub

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

var ErrIndexNotFound = fmt.Errorf("index not found")

func UpdateHubIdx(hub *csconfig.Hub) error {
	bidx, err := DownloadHubIdx(hub)
	if err != nil {
		return fmt.Errorf("failed to download index: %w", err)
	}
	ret, err := LoadPkgIndex(bidx)
	if err != nil {
		if !errors.Is(err, ReferenceMissingError) {
			return fmt.Errorf("failed to read index: %w", err)
		}
	}
	hubIdx = ret
	if err, _ := LocalSync(hub); err != nil {
		return fmt.Errorf("failed to sync: %w", err)
	}
	return nil
}

func DownloadHubIdx(hub *csconfig.Hub) ([]byte, error) {
	log.Debugf("fetching index from branch %s (%s)", HubBranch, fmt.Sprintf(RawFileURLTemplate, HubBranch, HubIndexFile))
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(RawFileURLTemplate, HubBranch, HubIndexFile), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request for hub index: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed http request for hub index: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, ErrIndexNotFound
		}
		return nil, fmt.Errorf("bad http code %d while requesting %s", resp.StatusCode, req.URL.String())
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request answer for hub index: %w", err)
	}

	oldContent, err := os.ReadFile(hub.HubIndexFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warningf("failed to read hub index: %s", err)
		}
	} else if bytes.Equal(body, oldContent) {
		log.Info("hub index is up to date")
		// write it anyway, can't hurt
	}

	file, err := os.OpenFile(hub.HubIndexFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)

	if err != nil {
		return nil, fmt.Errorf("while opening hub index file: %w", err)
	}
	defer file.Close()

	wsize, err := file.WriteString(string(body))
	if err != nil {
		return nil, fmt.Errorf("while writing hub index file: %w", err)
	}
	log.Infof("Wrote new %d bytes index to %s", wsize, hub.HubIndexFile)
	return body, nil
}

// DownloadLatest will download the latest version of Item to the tdir directory
func DownloadLatest(hub *csconfig.Hub, target Item, overwrite bool, updateOnly bool) (Item, error) {
	var err error

	log.Debugf("Downloading %s %s", target.Type, target.Name)
	if target.Type != COLLECTIONS {
		if !target.Installed && updateOnly && target.Downloaded {
			log.Debugf("skipping upgrade of %s : not installed", target.Name)
			return target, nil
		}
		return DownloadItem(hub, target, overwrite)
	}

	// collection
	var tmp = [][]string{target.Parsers, target.PostOverflows, target.Scenarios, target.Collections}
	for idx, ptr := range tmp {
		ptrtype := ItemTypes[idx]
		for _, p := range ptr {
			val, ok := hubIdx[ptrtype][p]
			if !ok {
				return target, fmt.Errorf("required %s %s of %s doesn't exist, abort", ptrtype, p, target.Name)
			}

			if !val.Installed && updateOnly && val.Downloaded {
				log.Debugf("skipping upgrade of %s : not installed", target.Name)
				continue
			}

			log.Debugf("Download %s sub-item : %s %s (%t -> %t)", target.Name, ptrtype, p, target.Installed, updateOnly)
			//recurse as it's a collection
			if ptrtype == COLLECTIONS {
				log.Tracef("collection, recurse")
				hubIdx[ptrtype][p], err = DownloadLatest(hub, val, overwrite, updateOnly)
				if err != nil {
					return target, fmt.Errorf("while downloading %s: %w", val.Name, err)
				}
			}
			item, err := DownloadItem(hub, val, overwrite)
			if err != nil {
				return target, fmt.Errorf("while downloading %s: %w", val.Name, err)
			}

			// We need to enable an item when it has been added to a collection since latest release of the collection.
			// We check if val.Downloaded is false because maybe the item has been disabled by the user.
			if !item.Installed && !val.Downloaded {
				if item, err = EnableItem(hub, item); err != nil {
					return target, fmt.Errorf("enabling '%s': %w", item.Name, err)
				}
			}
			hubIdx[ptrtype][p] = item
		}
	}
	target, err = DownloadItem(hub, target, overwrite)
	if err != nil {
		return target, fmt.Errorf("failed to download item : %s", err)
	}
	return target, nil
}

func DownloadItem(hub *csconfig.Hub, target Item, overwrite bool) (Item, error) {
	var tdir = hub.HubDir
	var dataFolder = hub.DataDir
	/*if user didn't --force, don't overwrite local, tainted, up-to-date files*/
	if !overwrite {
		if target.Tainted {
			log.Debugf("%s : tainted, not updated", target.Name)
			return target, nil
		}
		if target.UpToDate {
			log.Debugf("%s : up-to-date, not updated", target.Name)
			//  We still have to check if data files are present
		}
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(RawFileURLTemplate, HubBranch, target.RemotePath), nil)
	if err != nil {
		return target, fmt.Errorf("while downloading %s: %w", req.URL.String(), err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return target, fmt.Errorf("while downloading %s: %w", req.URL.String(), err)
	}
	if resp.StatusCode != http.StatusOK {
		return target, fmt.Errorf("bad http code %d for %s", resp.StatusCode, req.URL.String())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return target, fmt.Errorf("while reading %s: %w", req.URL.String(), err)
	}
	h := sha256.New()
	if _, err := h.Write(body); err != nil {
		return target, fmt.Errorf("while hashing %s: %w", target.Name, err)
	}
	meow := fmt.Sprintf("%x", h.Sum(nil))
	if meow != target.Versions[target.Version].Digest {
		log.Errorf("Downloaded version doesn't match index, please 'hub update'")
		log.Debugf("got %s, expected %s", meow, target.Versions[target.Version].Digest)
		return target, fmt.Errorf("invalid download hash for %s", target.Name)
	}
	//all good, install
	//check if parent dir exists
	tmpdirs := strings.Split(tdir+"/"+target.RemotePath, "/")
	parent_dir := strings.Join(tmpdirs[:len(tmpdirs)-1], "/")

	/*ensure that target file is within target dir*/
	finalPath, err := filepath.Abs(tdir + "/" + target.RemotePath)
	if err != nil {
		return target, fmt.Errorf("filepath.Abs error on %s: %w", tdir+"/"+target.RemotePath, err)
	}
	if !strings.HasPrefix(finalPath, tdir) {
		return target, fmt.Errorf("path %s escapes %s, abort", target.RemotePath, tdir)
	}
	/*check dir*/
	if _, err = os.Stat(parent_dir); os.IsNotExist(err) {
		log.Debugf("%s doesn't exist, create", parent_dir)
		if err := os.MkdirAll(parent_dir, os.ModePerm); err != nil {
			return target, fmt.Errorf("while creating parent directories: %w", err)
		}
	}
	/*check actual file*/
	if _, err = os.Stat(finalPath); !os.IsNotExist(err) {
		log.Warningf("%s : overwrite", target.Name)
		log.Debugf("target: %s/%s", tdir, target.RemotePath)
	} else {
		log.Infof("%s : OK", target.Name)
	}

	f, err := os.OpenFile(tdir+"/"+target.RemotePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return target, fmt.Errorf("while opening file: %w", err)
	}
	defer f.Close()
	_, err = f.WriteString(string(body))
	if err != nil {
		return target, fmt.Errorf("while writing file: %w", err)
	}
	target.Downloaded = true
	target.Tainted = false
	target.UpToDate = true

	if err = downloadData(dataFolder, overwrite, bytes.NewReader(body)); err != nil {
		return target, fmt.Errorf("while downloading data for %s: %w", target.FileName, err)
	}

	hubIdx[target.Type][target.Name] = target
	return target, nil
}

func DownloadDataIfNeeded(hub *csconfig.Hub, target Item, force bool) error {
	var (
		dataFolder = hub.DataDir
		itemFile   *os.File
		err        error
	)
	itemFilePath := fmt.Sprintf("%s/%s/%s/%s", hub.ConfigDir, target.Type, target.Stage, target.FileName)
	if itemFile, err = os.Open(itemFilePath); err != nil {
		return fmt.Errorf("while opening %s: %w", itemFilePath, err)
	}
	defer itemFile.Close()
	if err = downloadData(dataFolder, force, itemFile); err != nil {
		return fmt.Errorf("while downloading data for %s: %w", itemFilePath, err)
	}
	return nil
}

func downloadData(dataFolder string, force bool, reader io.Reader) error {
	var err error
	dec := yaml.NewDecoder(reader)

	for {
		data := &DataSet{}
		err = dec.Decode(data)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("while reading file: %w", err)
		}

		download := false
		for _, dataS := range data.Data {
			if _, err := os.Stat(filepath.Join(dataFolder, dataS.DestPath)); os.IsNotExist(err) {
				download = true
			}
		}
		if download || force {
			err = GetData(data.Data, dataFolder)
			if err != nil {
				return fmt.Errorf("while getting data: %w", err)
			}
		}
	}
	return nil
}
