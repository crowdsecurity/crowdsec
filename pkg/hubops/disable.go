package hubops

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// RemoveInstallLink removes the item's symlink between the installation directory and the local hub.
func RemoveInstallLink(i *cwhub.Item) error {
	stat, err := os.Lstat(i.State.LocalPath)
	if err != nil {
		return err
	}

	// if it's managed by hub, it's a symlink to csconfig.GConfig.hub.HubDir / ...
	if stat.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%s isn't managed by hub", i.Name)
	}

	hubpath, err := os.Readlink(i.State.LocalPath)
	if err != nil {
		return fmt.Errorf("while reading symlink: %w", err)
	}

	src, err := i.DownloadPath()
	if err != nil {
		return err
	}

	if hubpath != src {
		return fmt.Errorf("%s isn't managed by hub", i.Name)
	}

	if err := os.Remove(i.State.LocalPath); err != nil {
		return fmt.Errorf("while removing symlink: %w", err)
	}

	return nil
}

// DisableCommand uninstalls an item and its dependencies, ensuring that no
// sub-item is left in an inconsistent state.
type DisableCommand struct {
	Item  *cwhub.Item
	Force bool
}

func NewDisableCommand(item *cwhub.Item, force bool) *DisableCommand {
	return &DisableCommand{Item: item, Force: force}
}

func (c *DisableCommand) Prepare(plan *ActionPlan) (bool, error) {
	i := c.Item

	if i.State.IsLocal() {
		plan.Warning(i.FQName() + " is a local item, please delete manually")
		return false, nil
	}

	if i.State.Tainted && !c.Force {
		return false, fmt.Errorf("%s is tainted, use '--force' to remove", i.Name)
	}

	if !i.State.Installed {
		return false, nil
	}

	subsToRemove, err := i.SafeToRemoveDeps()
	if err != nil {
		return false, err
	}

	for _, sub := range subsToRemove {
		if !sub.State.Installed {
			continue
		}

		if err := plan.AddCommand(NewDisableCommand(sub, c.Force)); err != nil {
			return false, err
		}
	}

	return true, nil
}

func (c *DisableCommand) Run(ctx context.Context, plan *ActionPlan) error {
	i := c.Item

	fmt.Println("disabling " + colorizeItemName(i.FQName()))

	if err := RemoveInstallLink(i); err != nil {
		return fmt.Errorf("while disabling %s: %w", i.FQName(), err)
	}

	plan.ReloadNeeded = true

	i.State.Installed = false
	i.State.Tainted = false

	return nil
}

func (c *DisableCommand) OperationType() string {
	return "disable"
}

func (c *DisableCommand) ItemType() string {
	return c.Item.Type
}

func (c *DisableCommand) Detail() string {
	return colorizeItemName(c.Item.Name)
}
