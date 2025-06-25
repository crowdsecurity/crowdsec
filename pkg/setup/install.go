package setup

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/hubops"
)

// AcquisDocument is created from a ServicePlan. It represents a single YAML document, and can be part of a multi-document file.
type AcquisDocument struct {
	AcquisFilename string
	DataSource     map[string]any
}

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

// GenerateAcquisition generates the datasource configuration, as a single file or multiple files in a directory.
func GenerateAcquisition(acquisitionSpecs []AcquisitionSpec, toDir string) error {
	info, err := os.Stat(toDir)
	if err != nil {
		return err
	}

	// check explicitly because os.Create would report the same error with the file's path instead of the directory's path
	if !info.IsDir() {
		return fmt.Errorf("open %s: not a directory", toDir)
	}

	for _, spec := range acquisitionSpecs {
		if spec.Datasource == nil {
			continue
		}

		if err := spec.WriteTo(toDir); err != nil {
			return err
		}
	}

	return nil
}
