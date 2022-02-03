package cwhub

import (
	"bytes"
	"crypto/sha256"
	"io"
	"path"
	"path/filepath"
	"sort"

	//"errors"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	//"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func UpdateHubIdx(hub *csconfig.Hub) error {

	bidx, err := DownloadHubIdx(hub)
	if err != nil {
		return errors.Wrap(err, "failed to download index")
	}
	ret, err := LoadPkgIndex(bidx)
	if err != nil {
		if !errors.Is(err, ReferenceMissingError) {
			return errors.Wrap(err, "failed to read index")
		}
	}
	hubIdx = ret
	if err, _ := LocalSync(hub); err != nil {
		return errors.Wrap(err, "failed to sync")
	}
	return nil
}

func DownloadHubIdx(hub *csconfig.Hub) ([]byte, error) {
	log.Debugf("fetching index from branch %s (%s)", HubBranch, fmt.Sprintf(RawFileURLTemplate, HubBranch, HubIndexFile))
	req, err := http.NewRequest("GET", fmt.Sprintf(RawFileURLTemplate, HubBranch, HubIndexFile), nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build request for hub index")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed http request for hub index")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bad http code %d while requesting %s", resp.StatusCode, req.URL.String())
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read request answer for hub index")
	}
	file, err := os.OpenFile(hub.HubIndexFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)

	if err != nil {
		return nil, errors.Wrap(err, "while opening hub index file")
	}
	defer file.Close()

	wsize, err := file.WriteString(string(body))
	if err != nil {
		return nil, errors.Wrap(err, "while writting hub index file")
	}
	log.Infof("Wrote new %d bytes index to %s", wsize, hub.HubIndexFile)
	return body, nil
}

//DownloadLatest will download the latest version of Item to the tdir directory
func DownloadLatest(hub *csconfig.Hub, target Item, overwrite bool, updateOnly bool) (Item, error) {
	var err error

	if target.Type == COLLECTIONS {
		var tmp = [][]string{target.Parsers, target.PostOverflows, target.Scenarios, target.Collections}
		for idx, ptr := range tmp {
			ptrtype := ItemTypes[idx]
			for _, p := range ptr {
				val, ok := hubIdx[ptrtype][p]
				if !ok {
					return target, fmt.Errorf("required %s %s of %s doesn't exist, abort", ptrtype, p, target.Name)
				}

				if !val.Installed && updateOnly {
					log.Debugf("skipping upgrade of %s : not installed", target.Name)
					continue
				}
				log.Debugf("Download %s sub-item : %s %s (%t -> %t)", target.Name, ptrtype, p, target.Installed, updateOnly)
				//recurse as it's a collection
				if ptrtype == COLLECTIONS {
					log.Tracef("collection, recurse")
					hubIdx[ptrtype][p], err = DownloadLatest(hub, val, overwrite, updateOnly)
					if err != nil {
						return target, errors.Wrap(err, fmt.Sprintf("while downloading %s", val.Name))
					}
				}
				item, err := DownloadItem(hub, val, overwrite)
				if err != nil {
					return target, errors.Wrap(err, fmt.Sprintf("while downloading %s", val.Name))
				}

				// We need to enable an item when it has been added to a collection since latest release of the collection.
				// We check if val.Downloaded is false because maybe the item has been disabled by the user.
				if !item.Installed && !val.Downloaded {
					if item, err = EnableItem(hub, item); err != nil {
						return target, errors.Wrapf(err, "enabling '%s'", item.Name)
					}
				}
				hubIdx[ptrtype][p] = item
			}
		}
		target, err = DownloadItem(hub, target, overwrite)
		if err != nil {
			return target, fmt.Errorf("failed to download item : %s", err)
		}
	} else {
		if !target.Installed && updateOnly {
			log.Debugf("skipping upgrade of %s : not installed", target.Name)
			return target, nil
		}
		return DownloadItem(hub, target, overwrite)
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
			//  We still have to check if data files are present
			log.Debugf("%s : up-to-date, not updated", target.Name)
			data, err := os.ReadFile(target.LocalPath)
			if err != nil {
				return target, err
			}
			if err := downloadData(dataFolder, target.Author, overwrite, bytes.NewReader(data)); err != nil {
				return target, errors.Wrapf(err, "while downloading data for %s", target.FileName)
			}
			return target, nil
		}
	}
	log.Debugf("Downloading %s %s", target.Type, target.Name)
	req, err := http.NewRequest("GET", fmt.Sprintf(RawFileURLTemplate, HubBranch, target.RemotePath), nil)
	if err != nil {
		return target, errors.Wrap(err, fmt.Sprintf("while downloading %s", req.URL.String()))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return target, errors.Wrap(err, fmt.Sprintf("while downloading %s", req.URL.String()))
	}
	if resp.StatusCode != 200 {
		return target, fmt.Errorf("bad http code %d for %s", resp.StatusCode, req.URL.String())
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return target, errors.Wrap(err, fmt.Sprintf("while reading %s", req.URL.String()))
	}
	h := sha256.New()
	if _, err := h.Write([]byte(body)); err != nil {
		return target, errors.Wrap(err, fmt.Sprintf("while hashing %s", target.Name))
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
		return target, errors.Wrapf(err, "Abs error on %s", tdir+"/"+target.RemotePath)
	}
	if !strings.HasPrefix(finalPath, tdir) {
		return target, fmt.Errorf("path %s escapes %s, abort", target.RemotePath, tdir)
	}
	/*check dir*/
	if _, err = os.Stat(parent_dir); os.IsNotExist(err) {
		log.Debugf("%s doesn't exist, create", parent_dir)
		if err := os.MkdirAll(parent_dir, os.ModePerm); err != nil {
			return target, errors.Wrap(err, "while creating parent directories")
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
		return target, errors.Wrap(err, "while opening file")
	}
	defer f.Close()
	_, err = f.WriteString(string(body))
	if err != nil {
		return target, errors.Wrap(err, "while writting file")
	}
	target.Downloaded = true
	target.Tainted = false
	target.UpToDate = true

	if err = downloadData(dataFolder, target.Author, overwrite, bytes.NewReader(body)); err != nil {
		return target, errors.Wrapf(err, "while downloading data for %s", target.FileName)
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
		return errors.Wrapf(err, "while opening %s", itemFilePath)
	}
	if err = downloadData(dataFolder, target.Author, force, itemFile); err != nil {
		return errors.Wrapf(err, "while downloading data for %s", itemFilePath)
	}
	return nil
}

func downloadData(dataFolder string, parentItemAuthor string, force bool, reader io.Reader) error {
	var err error
	dec := yaml.NewDecoder(reader)
	for {
		data := &types.DataSet{}
		err = dec.Decode(data)
		if err != nil {
			if err != io.EOF {
				return errors.Wrap(err, "while reading file")
			}
			break
		}

		for _, dataS := range data.Data {
			download := false
			dfPath := path.Join(dataFolder, dataS.DestPath)
			dataFileName := strings.Split(dataS.DestPath, ".")[0]
			_, downloadFromHub := hubIdx[DATA_FILES][dataFileName]
			if downloadFromHub {
				dataS.SourceURL = fmt.Sprintf(RawFileURLTemplate, HubBranch, hubIdx[DATA_FILES][dataFileName].RemotePath)
			}

			if _, err := os.Stat(dfPath); os.IsNotExist(err) {
				download = true
			} else if downloadFromHub {
				sha, err := getSHA256(dfPath)
				if err != nil {
					return err
				}
				download = dataFileHasUpdates(sha, dataFileName)
			}

			log.Infof("%v has updates=%v", dataFileName, download)

			if download || force {
				err = types.GetData(dataS, dataFolder)
				if err != nil {
					return errors.Wrap(err, "while getting data")
				}
			}

		}
	}

	return nil
}

// Checks if the provided data file is latest. Only files which  are available in hub should
// be checked for.
func dataFileHasUpdates(fileSha string, dataFileName string) bool {
	dataItem := hubIdx[DATA_FILES][dataFileName]
	versions := make([]string, 0, len(dataItem.Versions))
	for k := range dataItem.Versions {
		versions = append(versions, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(versions)))
	for i, version := range versions {
		if fileSha != dataItem.Versions[version].Digest {
			continue
		}
		log.Debugf("data file %s matched sha with version %s", dataFileName, version)
		if i != 0 {
			log.Debugf("data file %s is outdated, updating to version %s", dataFileName, versions[0])
			return true
		}
		break
	}
	return false
}
