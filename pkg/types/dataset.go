package types

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"time"

	log "github.com/sirupsen/logrus"
)

type DataSource struct {
	SourceURL string `yaml:"source_url"`
	DestPath  string `yaml:"dest_file"`
	Type      string `yaml:"type"`
	//Control cache strategy on expensive regexps
	Cache    *bool          `yaml:"cache"`
	Strategy *string        `yaml:"strategy"`
	Size     *int           `yaml:"size"`
	TTL      *time.Duration `yaml:"ttl"`
}

type DataSet struct {
	Data []*DataSource `yaml:"data,omitempty"`
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

	_, err = file.WriteString(string(body))
	if err != nil {
		return err
	}

	err = file.Sync()
	if err != nil {
		return err
	}

	return nil
}

func GetData(data []*DataSource, dataDir string) error {
	for _, dataS := range data {
		destPath := path.Join(dataDir, dataS.DestPath)
		log.Infof("downloading data '%s' in '%s'", dataS.SourceURL, destPath)
		err := downloadFile(dataS.SourceURL, destPath)
		if err != nil {
			return err
		}
	}

	return nil
}
