package cwhub

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// The DataSet is a list of data sources required by an item (built from the data: section in the yaml).
type DataSet struct {
	Data []types.DataSource `yaml:"data,omitempty"`
}

// downloadFile downloads a file and writes it to disk, with no hash verification.
func downloadFile(url string, destPath string) error {
	resp, err := hubClient.Get(url)
	if err != nil {
		return fmt.Errorf("while downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad http code %d for %s", resp.StatusCode, url)
	}

	file, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// avoid reading the whole file in memory
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return err
	}

	if err = file.Sync(); err != nil {
		return err
	}

	return nil
}

// needsUpdate checks if a data file has to be downloaded (or updated).
// if the local file doesn't exist, update.
// if the remote is newer than the local file, update.
// if the remote has no modification date, but local file has been modified > a week ago, update.
func needsUpdate(destPath string, url string, logger *logrus.Logger) bool {
	fileInfo, err := os.Stat(destPath)
	switch {
	case os.IsNotExist(err):
		return true
	case err != nil:
		logger.Errorf("while getting %s: %s", destPath, err)
		return true
	}

	resp, err := hubClient.Head(url)
	if err != nil {
		logger.Errorf("while getting %s: %s", url, err)
		// Head failed, Get would likely fail too -> no update
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Errorf("bad http code %d for %s", resp.StatusCode, url)
		return false
	}

	// update if local file is older than this
	shelfLife := 7 * 24 * time.Hour

	lastModify := fileInfo.ModTime()

	localIsOld := lastModify.Add(shelfLife).Before(time.Now())

	remoteLastModified := resp.Header.Get("Last-Modified")
	if remoteLastModified == "" {
		if localIsOld {
			logger.Infof("no last modified date for %s, but local file is older than %s", url, shelfLife)
		}
		return localIsOld
	}

	lastAvailable, err := time.Parse(time.RFC1123, remoteLastModified)
	if err != nil {
		logger.Warningf("while parsing last modified date for %s: %s", url, err)
		return localIsOld
	}

	if lastModify.Before(lastAvailable) {
		logger.Infof("new version available, updating %s", destPath)
		return true
	}

	return false
}

// downloadDataSet downloads all the data files for an item.
func downloadDataSet(dataFolder string, force bool, reader io.Reader, logger *logrus.Logger) error {
	dec := yaml.NewDecoder(reader)

	for {
		data := &DataSet{}

		if err := dec.Decode(data); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return fmt.Errorf("while reading file: %w", err)
		}

		for _, dataS := range data.Data {
			destPath, err := safePath(dataFolder, dataS.DestPath)
			if err != nil {
				return err
			}

			if force || needsUpdate(destPath, dataS.SourceURL, logger) {
				logger.Debugf("downloading %s in %s", dataS.SourceURL, destPath)
				if err := downloadFile(dataS.SourceURL, destPath); err != nil {
					return fmt.Errorf("while getting data: %w", err)
				}
			}
		}
	}

	return nil
}
