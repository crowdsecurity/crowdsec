package hubops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/downloader"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// DownloadCommand handles the downloading of hub items.
// It ensures that items are fetched from the hub (or from the index file if it also has content)
// managing dependencies and verifying the integrity of downloaded content.
// This is used by "cscli install" and "cscli upgrade".
// Tainted items require the force parameter, local items are skipped.
type DownloadCommand struct {
	Item            *cwhub.Item
	Force           bool
	contentProvider cwhub.ContentProvider
}

func NewDownloadCommand(item *cwhub.Item, contentProvider cwhub.ContentProvider, force bool) *DownloadCommand {
	return &DownloadCommand{Item: item, Force: force, contentProvider: contentProvider}
}

func (c *DownloadCommand) Prepare(plan *ActionPlan) (bool, error) {
	i := c.Item

	if i.State.IsLocal() {
		plan.Info(i.FQName() + " - not downloading local item")
		return false, nil
	}

	// XXX: if it's tainted do we upgrade the dependencies anyway?
	if i.State.Tainted && !c.Force {
		plan.Warning(i.FQName() + " is tainted, use '--force' to overwrite")
		return false, nil
	}

	toDisable := make(map[*cwhub.Item]struct{})

	var disableKeys []*cwhub.Item

	if i.State.Installed {
		for sub := range i.CurrentDependencies().SubItems(plan.hub) {
			disableKeys = append(disableKeys, sub)
			toDisable[sub] = struct{}{}
		}
	}

	for sub := range i.LatestDependencies().SubItems(plan.hub) {
		if err := plan.AddCommand(NewDownloadCommand(sub, c.contentProvider, c.Force)); err != nil {
			return false, err
		}

		if i.State.Installed {
			// ensure the _new_ dependencies are installed too
			if err := plan.AddCommand(NewEnableCommand(sub, c.Force)); err != nil {
				return false, err
			}

			for _, sub2 := range disableKeys {
				if sub2 == sub {
					delete(toDisable, sub)
				}
			}
		}
	}

	for sub := range toDisable {
		if err := plan.AddCommand(NewDisableCommand(sub, c.Force)); err != nil {
			return false, err
		}
	}

	if i.State.Downloaded && i.State.UpToDate {
		return false, nil
	}

	return true, nil
}

// The DataSet is a list of data sources required by an item (built from the data: section in the yaml).
type DataSet struct {
	Data []types.DataSource `yaml:"data,omitempty"`
}

// downloadDataSet downloads all the data files for an item.
func downloadDataSet(ctx context.Context, dataFolder string, force bool, reader io.Reader) (bool, error) {
	needReload := false

	dec := yaml.NewDecoder(reader)

	for {
		data := &DataSet{}

		if err := dec.Decode(data); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return needReload, fmt.Errorf("while reading file: %w", err)
		}

		for _, dataS := range data.Data {
			if dataS.SourceURL == "" {
				continue
			}

			// XXX: check context cancellation
			destPath, err := cwhub.SafePath(dataFolder, dataS.DestPath)
			if err != nil {
				return needReload, err
			}

			d := downloader.
				New().
				WithHTTPClient(cwhub.HubClient).
				ToFile(destPath).
				CompareContent().
				BeforeRequest(func(req *http.Request) {
					fmt.Printf("downloading %s\n", req.URL)
				}).
				WithLogger(logrus.WithField("url", dataS.SourceURL))

			if !force {
				d = d.WithLastModified().
					WithShelfLife(7 * 24 * time.Hour)
			}

			downloaded, err := d.Download(ctx, dataS.SourceURL)
			if err != nil {
				return needReload, fmt.Errorf("while getting data: %w", err)
			}

			needReload = needReload || downloaded
		}
	}

	return needReload, nil
}

func (c *DownloadCommand) Run(ctx context.Context, plan *ActionPlan) error {
	i := c.Item

	fmt.Printf("downloading %s\n", colorizeItemName(i.FQName()))

	// ensure that target file is within target dir
	finalPath, err := i.DownloadPath()
	if err != nil {
		return err
	}

	downloaded, _, err := i.FetchContentTo(ctx, c.contentProvider, finalPath)
	if err != nil {
		return fmt.Errorf("%s: %w", i.FQName(), err)
	}

	if downloaded {
		plan.ReloadNeeded = true
	}

	i.State.Downloaded = true
	i.State.Tainted = false
	i.State.UpToDate = true

	// read content to get the list of data files
	reader, err := os.Open(finalPath)
	if err != nil {
		return fmt.Errorf("while opening %s: %w", finalPath, err)
	}

	defer reader.Close()

	needReload, err := downloadDataSet(ctx, plan.hub.GetDataDir(), c.Force, reader)
	if err != nil {
		return fmt.Errorf("while downloading data for %s: %w", i.FileName, err)
	}

	if needReload {
		plan.ReloadNeeded = true
	}

	return nil
}

func (c *DownloadCommand) OperationType() string {
	return "download"
}

func (c *DownloadCommand) ItemType() string {
	return c.Item.Type
}

func (c *DownloadCommand) Detail() string {
	i := c.Item

	version := color.YellowString(i.Version)

	if i.State.Downloaded {
		version = c.Item.State.LocalVersion + " -> " + color.YellowString(i.Version)
	}

	return colorizeItemName(c.Item.Name) + " (" + version + ")"
}
