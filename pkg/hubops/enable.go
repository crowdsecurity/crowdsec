package hubops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// EnableCommand installs a hub item and its dependencies.
// In case this command is called during an upgrade, the sub-items list it taken from the
// latest version in the index, otherwise from the version that is currently installed.
type EnableCommand struct {
	Item       *cwhub.Item
	Force      bool
	FromLatest bool
}

func NewEnableCommand(item *cwhub.Item, force bool) *EnableCommand {
	return &EnableCommand{Item: item, Force: force}
}

func (c *EnableCommand) Prepare(plan *ActionPlan) (bool, error) {
	var dependencies cwhub.Dependencies

	i := c.Item

	if c.FromLatest {
		// we are upgrading
		dependencies = i.LatestDependencies()
	} else {
		dependencies = i.CurrentDependencies()
	}

	for sub := range dependencies.SubItems(plan.hub) {
		if err := plan.AddCommand(NewEnableCommand(sub, c.Force)); err != nil {
			return false, err
		}
	}

	if i.State.Installed {
		return false, nil
	}

	return true, nil
}

// CreateInstallLink creates a symlink between the actual config file at hub.HubDir and hub.ConfigDir.
func CreateInstallLink(i *cwhub.Item) error {
	dest, err := i.InstallPath()
	if err != nil {
		return err
	}

	destDir := filepath.Dir(dest)
	if err = os.MkdirAll(destDir, os.ModePerm); err != nil {
		return fmt.Errorf("while creating %s: %w", destDir, err)
	}

	if _, err = os.Lstat(dest); err == nil {
		// already exists
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat %s: %w", dest, err)
	}

	src, err := i.DownloadPath()
	if err != nil {
		return err
	}

	if err = os.Symlink(src, dest); err != nil {
		return fmt.Errorf("while creating symlink from %s to %s: %w", src, dest, err)
	}

	return nil
}

func (c *EnableCommand) Run(ctx context.Context, plan *ActionPlan) error {
	i := c.Item

	fmt.Println("enabling " + colorizeItemName(i.FQName()))

	if !i.State.Downloaded {
		// XXX: this a warning?
		return fmt.Errorf("can't enable %s: not downloaded", i.FQName())
	}

	if err := CreateInstallLink(i); err != nil {
		return fmt.Errorf("while enabling %s: %w", i.FQName(), err)
	}

	plan.ReloadNeeded = true

	i.State.Installed = true
	i.State.Tainted = false

	return nil
}

func (c *EnableCommand) OperationType() string {
	return "enable"
}

func (c *EnableCommand) ItemType() string {
	return c.Item.Type
}

func (c *EnableCommand) Detail() string {
	return colorizeItemName(c.Item.Name)
}
