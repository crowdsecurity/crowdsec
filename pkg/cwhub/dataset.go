package cwhub

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type DataSet struct {
	Data []types.DataSource `yaml:"data,omitempty"`
}

func downloadFile(url string, destPath string) error {
	log.Debugf("downloading %s in %s", url, destPath)

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

	file, err := os.OpenFile(destPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(body)
	if err != nil {
		return err
	}

	if err = file.Sync(); err != nil {
		return err
	}

	return nil
}

func GetData(data []types.DataSource, dataDir string) error {
	for _, dataS := range data {
		destPath := filepath.Join(dataDir, dataS.DestPath)
		log.Infof("downloading data '%s' in '%s'", dataS.SourceURL, destPath)

		if err := downloadFile(dataS.SourceURL, destPath); err != nil {
			return err
		}
	}

	return nil
}

// downloadData downloads the data files for an item
func downloadData(dataFolder string, force bool, reader io.Reader) error {
	dec := yaml.NewDecoder(reader)

	for {
		data := &DataSet{}

		if err := dec.Decode(data); err != nil {
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
			if err := GetData(data.Data, dataFolder); err != nil {
				return fmt.Errorf("while getting data: %w", err)
			}
		}
	}

	return nil
}
