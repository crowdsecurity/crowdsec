package cwhub

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type DataSet struct {
	Data []*types.DataSource `yaml:"data,omitempty"`
}

func downloadFile(url string, destPath string) error {
	log.Debugf("downloading %s in %s", url, destPath)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download response 'HTTP %d' : %s", resp.StatusCode, string(body))
	}

	file, err := os.OpenFile(destPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	_, err = file.Write(body)
	if err != nil {
		return err
	}

	err = file.Sync()
	if err != nil {
		return err
	}

	return nil
}

func GetData(data []*types.DataSource, dataDir string) error {
	for _, dataS := range data {
		destPath := filepath.Join(dataDir, dataS.DestPath)
		log.Infof("downloading data '%s' in '%s'", dataS.SourceURL, destPath)

		err := downloadFile(dataS.SourceURL, destPath)
		if err != nil {
			return err
		}
	}

	return nil
}
