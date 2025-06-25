package setup

import (
	"context"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/hubops"
)

// InstallHubItems installs the objects recommended in a setup file.
func InstallHubItems(ctx context.Context, hub *cwhub.Hub, contentProvider cwhub.ContentProvider, hubSpecs []HubSpec, interactive, dryRun, showPlan, verbosePlan bool) error {
	plan := hubops.NewActionPlan(hub)

	for _, itemMap := range hubSpecs {
		if len(itemMap) == 0 {
			continue
		}

		for itemType, itemNames := range itemMap {
			for _, itemName := range itemNames {
				fqName := itemType + ":" + itemName
				item, err  := hub.GetItemFQ(fqName)
				if err != nil {
					return err
				}

				if err := plan.AddCommand(hubops.NewDownloadCommand(item, contentProvider, false)); err != nil {
					return err
				}

				if err := plan.AddCommand(hubops.NewEnableCommand(item, false)); err != nil {
					return err
				}
			}
		}
	}

	return plan.Execute(ctx, interactive, dryRun, showPlan, verbosePlan)
}
