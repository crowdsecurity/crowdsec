package hubops

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// PurgeCommand removes the downloaded content of a hub item, effectively
// removing it from the local system. This command also removes the sub-items
// but not the associated data files.
type PurgeCommand struct {
	Item  *cwhub.Item
	Force bool
}

func NewPurgeCommand(item *cwhub.Item, force bool) *PurgeCommand {
	return &PurgeCommand{Item: item, Force: force}
}

func (c *PurgeCommand) Prepare(plan *ActionPlan) (bool, error) {
	i := c.Item

	if i.State.IsLocal() {
		// not downloaded, by definition
		return false, nil
	}

	if i.State.Tainted && !c.Force {
		return false, fmt.Errorf("%s is tainted, use '--force' to remove", i.Name)
	}

	subsToRemove, err := i.SafeToRemoveDeps()
	if err != nil {
		return false, err
	}

	for _, sub := range subsToRemove {
		if err := plan.AddCommand(NewPurgeCommand(sub, c.Force)); err != nil {
			return false, err
		}
	}

	if !i.State.Downloaded {
		return false, nil
	}

	return true, nil
}

func (c *PurgeCommand) Run(ctx context.Context, plan *ActionPlan) error {
	i := c.Item

	fmt.Println("purging " + colorizeItemName(i.FQName()))

	src, err := i.DownloadPath()
	if err != nil {
		return err
	}

	if err := os.Remove(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return fmt.Errorf("while removing file: %w", err)
	}

	i.State.Downloaded = false
	i.State.Tainted = false
	i.State.UpToDate = false

	return nil
}

func (c *PurgeCommand) OperationType() string {
	return "purge (delete source)"
}

func (c *PurgeCommand) ItemType() string {
	return c.Item.Type
}

func (c *PurgeCommand) Detail() string {
	return colorizeItemName(c.Item.Name)
}
