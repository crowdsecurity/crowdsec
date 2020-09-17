package cwhub

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

func LoadHubIdx(cscli *csconfig.CscliCfg) error {
	bidx, err := ioutil.ReadFile(cscli.IndexPath)
	if err != nil {
		return err
	}
	ret, err := LoadPkgIndex(bidx)
	if err != nil {
		if !errors.Is(err, ReferenceMissingError) {
			log.Fatalf("Unable to load freshly downloaded index : %v.", err)
		}
	}
	hubIdx = ret
	if err := LocalSync(cscli); err != nil {
		log.Fatalf("Failed to sync Hub index with local deployment : %v", err)
	}
	return nil
}

func UpdateHubIdx(cscli *csconfig.CscliCfg) error {

	bidx, err := DownloadHubIdx(cscli)
	if err != nil {
		log.Fatalf("Unable to download index : %v.", err)
	}
	ret, err := LoadPkgIndex(bidx)
	if err != nil {
		if !errors.Is(err, ReferenceMissingError) {
			log.Fatalf("Unable to load freshly downloaded index : %v.", err)
		}
	}
	hubIdx = ret
	if err := LocalSync(cscli); err != nil {
		log.Fatalf("Failed to sync Hub index with local deployment : %v", err)
	}
	return nil
}

func DownloadHubIdx(cscli *csconfig.CscliCfg) ([]byte, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(RawFileURLTemplate, HubBranch, HubIndexFile), nil)
	if err != nil {
		log.Errorf("failed request : %s", err)
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf("failed request Do : %s", err)
		return nil, err
	}
	if resp.StatusCode != 200 {
		log.Errorf("got code %d while requesting %s, abort", resp.StatusCode,
			fmt.Sprintf(RawFileURLTemplate, HubBranch, HubIndexFile))
		return nil, fmt.Errorf("bad http code")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("failed request reqd: %s", err)
		return nil, err
	}
	file, err := os.OpenFile(cscli.IndexPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)

	if err != nil {
		log.Fatalf(err.Error())
	}
	defer file.Close()

	wsize, err := file.WriteString(string(body))
	if err != nil {
		log.Fatalf(err.Error())
	}
	log.Infof("Wrote new %d bytes index to %s", wsize, cscli.IndexPath)
	return body, nil
}

//DownloadLatest will download the latest version of Item to the tdir directory
func DownloadLatest(cscli *csconfig.CscliCfg, target Item, overwrite bool) (Item, error) {
	var err error

	log.Debugf("Downloading %s %s", target.Type, target.Name)
	if target.Type == COLLECTIONS {
		var tmp = [][]string{target.Parsers, target.PostOverflows, target.Scenarios, target.Collections}
		for idx, ptr := range tmp {
			ptrtype := ItemTypes[idx]
			for _, p := range ptr {
				if val, ok := hubIdx[ptrtype][p]; ok {
					log.Debugf("Download %s sub-item : %s %s", target.Name, ptrtype, p)
					//recurse as it's a collection
					if ptrtype == COLLECTIONS {
						log.Tracef("collection, recurse")
						hubIdx[ptrtype][p], err = DownloadLatest(cscli, val, overwrite)
						if err != nil {
							log.Errorf("Encountered error while downloading sub-item %s %s : %s.", ptrtype, p, err)
							return target, fmt.Errorf("encountered error while downloading %s for %s, abort", val.Name, target.Name)
						}
					}
					hubIdx[ptrtype][p], err = DownloadItem(cscli, val, overwrite)
					if err != nil {
						log.Errorf("Encountered error while downloading sub-item %s %s : %s.", ptrtype, p, err)
						return target, fmt.Errorf("encountered error while downloading %s for %s, abort", val.Name, target.Name)
					}
				} else {
					//log.Errorf("Referred %s %s in collection %s doesn't exist.", ptrtype, p, target.Name)
					return target, fmt.Errorf("required %s %s of %s doesn't exist, abort", ptrtype, p, target.Name)
				}
			}
		}
		target, err = DownloadItem(cscli, target, overwrite)
		if err != nil {
			return target, fmt.Errorf("failed to download item : %s", err)
		}
	} else {
		return DownloadItem(cscli, target, overwrite)
	}
	return target, nil
}

func DownloadItem(cscli *csconfig.CscliCfg, target Item, overwrite bool) (Item, error) {

	var tdir = cscli.InstallDir
	var dataFolder = cscli.DataDir
	/*if user didn't --force, don't overwrite local, tainted, up-to-date files*/
	if !overwrite {
		if target.Tainted {
			log.Debugf("%s : tainted, not updated", target.Name)
			return target, nil
		}
		if target.UpToDate {
			log.Debugf("%s : up-to-date, not updated", target.Name)
			return target, nil
		}
	}

	//log.Infof("Downloading %s to %s", target.Name, tdir)
	req, err := http.NewRequest("GET", fmt.Sprintf(RawFileURLTemplate, HubBranch, target.RemotePath), nil)
	if err != nil {
		log.Errorf("%s : request creation failed : %s", target.Name, err)
		return target, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf("%s : request failed : %s", target.Name, err)
		return target, err
	}
	if resp.StatusCode != 200 {
		log.Errorf("%s : non 200 response : %d", target.Name, resp.StatusCode)
		return target, fmt.Errorf("bad http code")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("%s : failed request read: %s", target.Name, err)
		return target, err
	}
	h := sha256.New()
	if _, err := h.Write([]byte(body)); err != nil {
		return target, fmt.Errorf("%s : failed to write : %s", target.Name, err)
	}
	meow := fmt.Sprintf("%x", h.Sum(nil))
	if meow != target.Versions[target.Version].Digest {
		log.Errorf("Downloaded version doesn't match index, please 'hub update'")
		log.Debugf("got %s, expected %s", meow, target.Versions[target.Version].Digest)
		return target, fmt.Errorf("invalid download hash")
	}
	//all good, install
	//check if parent dir exists
	tmpdirs := strings.Split(tdir+"/"+target.RemotePath, "/")
	parent_dir := strings.Join(tmpdirs[:len(tmpdirs)-1], "/")

	/*check dir*/
	if _, err = os.Stat(parent_dir); os.IsNotExist(err) {
		log.Debugf("%s doesn't exist, create", parent_dir)
		if err := os.MkdirAll(parent_dir, os.ModePerm); err != nil {
			return target, fmt.Errorf("unable to create parent directories")
		}
	}
	/*check actual file*/
	if _, err = os.Stat(tdir + "/" + target.RemotePath); !os.IsNotExist(err) {
		log.Warningf("%s : overwrite", target.Name)
		log.Debugf("target: %s/%s", tdir, target.RemotePath)
	} else {
		log.Infof("%s : OK", target.Name)
	}

	f, err := os.OpenFile(tdir+"/"+target.RemotePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return target, fmt.Errorf("failed to open destination file %s : %v", tdir+"/"+target.RemotePath, err)
	}
	defer f.Close()
	_, err = f.WriteString(string(body))
	if err != nil {
		return target, fmt.Errorf("failed to write destination file %s : %v", tdir+"/"+target.RemotePath, err)
	}
	target.Downloaded = true
	target.Tainted = false
	target.UpToDate = true

	dec := yaml.NewDecoder(bytes.NewReader(body))
	for {
		data := &types.DataSet{}
		err = dec.Decode(data)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return target, fmt.Errorf("unable to read file %s data: %s", tdir+"/"+target.RemotePath, err)
			}
		}
		err = types.GetData(data.Data, dataFolder)
		if err != nil {
			return target, fmt.Errorf("unable to get data: %s", err)
		}
	}
	hubIdx[target.Type][target.Name] = target
	return target, nil
}
