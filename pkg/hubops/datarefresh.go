package hubops

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// XXX: TODO: temporary for hubtests, but will have to go.
// DownloadDataIfNeeded downloads the data set for the item.
func DownloadDataIfNeeded(ctx context.Context, hub *cwhub.Hub, item *cwhub.Item, force bool) (bool, error) {
	itemFile, err := os.Open(item.State.LocalPath)
	if err != nil {
		return false, fmt.Errorf("while opening %s: %w", item.State.LocalPath, err)
	}

	defer itemFile.Close()

	needReload, err := downloadDataSet(ctx, hub.GetDataDir(), force, itemFile)
	if err != nil {
		return needReload, fmt.Errorf("while downloading data for %s: %w", item.State.LocalPath, err)
	}

	return needReload, nil
}

// DataRefreshCommand updates the data files associated with the installed hub items.
type DataRefreshCommand struct {
	Force bool
}

func NewDataRefreshCommand(force bool) *DataRefreshCommand {
	return &DataRefreshCommand{Force: force}
}

func (c *DataRefreshCommand) Prepare(plan *ActionPlan) (bool, error) {
	// we can't prepare much at this point because we don't know which data files yet,
	// and items needs to be downloaded/updated
	// evertyhing will be done in Run()
	return true, nil
}

func (c *DataRefreshCommand) Run(ctx context.Context, plan *ActionPlan) error {
	for _, itemType := range cwhub.ItemTypes {
		for _, item := range plan.hub.GetInstalledByType(itemType, true) {
			needReload, err := DownloadDataIfNeeded(ctx, plan.hub, item, c.Force)
			if err != nil {
				return err
			}

			plan.ReloadNeeded = plan.ReloadNeeded || needReload
		}
	}

	return nil
}

func (c *DataRefreshCommand) OperationType() string {
	return "check & update data files"
}

func (c *DataRefreshCommand) ItemType() string {
	return ""
}

func (c *DataRefreshCommand) Detail() string {
	return ""
}
