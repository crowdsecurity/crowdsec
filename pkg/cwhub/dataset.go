package cwhub

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type DataSet struct {
	Data []types.DataSource `yaml:"data,omitempty"`
}

// downloadFile downloads a file and writes it to disk, with no hash verification
func downloadFile(url string, destPath string) error {
	log.Debugf("downloading %s in %s", url, destPath)

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

// downloadDataSet downloads all the data files for an item
func downloadDataSet(dataFolder string, force bool, reader io.Reader) error {
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

			if _, err := os.Stat(destPath); os.IsNotExist(err) || force {
				log.Infof("downloading data '%s' in '%s'", dataS.SourceURL, destPath)

				if err := downloadFile(dataS.SourceURL, destPath); err != nil {
					return fmt.Errorf("while getting data: %w", err)
				}
			}
		}
	}

	return nil
}
