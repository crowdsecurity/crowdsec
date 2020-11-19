package cwhub

import (
	"bytes"
	"crypto/sha256"

	//"errors"
	"github.com/pkg/errors"

	//"errors"
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

func UpdateHubIdx(cscli *csconfig.CscliCfg) error {

	bidx, err := DownloadHubIdx(cscli)
	if err != nil {
		return errors.Wrap(err, "failed to download index")
	}
	ret, err := LoadPkgIndex(bidx)
	if err != nil {
		if !errors.Is(err, ReferenceMissingError) {
			return errors.Wrap(err, "failed to read index")
		}
	}
	HubIdx = ret
	if err := LocalSync(cscli); err != nil {
		return errors.Wrap(err, "failed to sync")
	}
	return nil
}

func DownloadHubIdx(cscli *csconfig.CscliCfg) ([]byte, error) {
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
	file, err := os.OpenFile(cscli.HubIndexFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)

	if err != nil {
		return nil, errors.Wrap(err, "while opening hub index file")
	}
	defer file.Close()

	wsize, err := file.WriteString(string(body))
	if err != nil {
		return nil, errors.Wrap(err, "while writting hub index file")
	}
	log.Infof("Wrote new %d bytes index to %s", wsize, cscli.HubIndexFile)
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
				if val, ok := HubIdx[ptrtype][p]; ok {
					log.Debugf("Download %s sub-item : %s %s", target.Name, ptrtype, p)
					//recurse as it's a collection
					if ptrtype == COLLECTIONS {
						log.Tracef("collection, recurse")
						HubIdx[ptrtype][p], err = DownloadLatest(cscli, val, overwrite)
						if err != nil {
							return target, errors.Wrap(err, fmt.Sprintf("while downloading %s", val.Name))
						}
					}
					HubIdx[ptrtype][p], err = DownloadItem(cscli, val, overwrite)
					if err != nil {
						return target, errors.Wrap(err, fmt.Sprintf("while downloading %s", val.Name))
					}
				} else {
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

	var tdir = cscli.HubDir
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

	/*check dir*/
	if _, err = os.Stat(parent_dir); os.IsNotExist(err) {
		log.Debugf("%s doesn't exist, create", parent_dir)
		if err := os.MkdirAll(parent_dir, os.ModePerm); err != nil {
			return target, errors.Wrap(err, "while creating parent directories")
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

	dec := yaml.NewDecoder(bytes.NewReader(body))
	for {
		data := &types.DataSet{}
		err = dec.Decode(data)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return target, errors.Wrap(err, "while reading file")
			}
		}
		err = types.GetData(data.Data, dataFolder)
		if err != nil {
			return target, errors.Wrap(err, "while getting data")
		}
	}
	HubIdx[target.Type][target.Name] = target
	return target, nil
}
