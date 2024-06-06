package cwhub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/downloader"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// The DataSet is a list of data sources required by an item (built from the data: section in the yaml).
type DataSet struct {
	Data []types.DataSource `yaml:"data,omitempty"`
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

			d := downloader.
				New().
				WithHTTPClient(hubClient).
				ToFile(destPath).
				CompareContent().
				WithLogger(logrus.WithFields(logrus.Fields{"url": dataS.SourceURL}))

			if !force {
				d = d.WithLastModified().
					WithShelfLife(7 * 24 * time.Hour)
			}

			ctx := context.TODO()

			downloaded, err := d.Download(ctx, dataS.SourceURL)
			if err != nil {
				return fmt.Errorf("while getting data: %w", err)
			}

			if downloaded {
				logger.Infof("Downloaded %s", destPath)
				// a check on stdout is used while scripting to know if the hub has been upgraded
				// and a configuration reload is required
				// TODO: use a better way to communicate this
				fmt.Printf("updated %s\n", destPath)
			}
		}
	}

	return nil
}
