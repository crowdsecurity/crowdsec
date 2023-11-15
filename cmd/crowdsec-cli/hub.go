package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewHubCmd() *cobra.Command {
	cmdHub := &cobra.Command{
		Use:   "hub [action]",
		Short: "Manage hub index",
		Long: `Hub management

List/update parsers/scenarios/postoverflows/collections from [Crowdsec Hub](https://hub.crowdsec.net).
The Hub is managed by cscli, to get the latest hub files from [Crowdsec Hub](https://hub.crowdsec.net), you need to update.`,
		Example: `cscli hub list
cscli hub update
cscli hub upgrade`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
	}

	cmdHub.AddCommand(NewHubListCmd())
	cmdHub.AddCommand(NewHubUpdateCmd())
	cmdHub.AddCommand(NewHubUpgradeCmd())

	return cmdHub
}

func runHubList(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	hub, err := require.Hub(csConfig, nil)
	if err != nil {
		return err
	}

	for _, v := range hub.Warnings {
		log.Info(v)
	}

	for _, line := range hub.ItemStats() {
		log.Info(line)
	}

	items := make(map[string][]*cwhub.Item)

	for _, itemType := range cwhub.ItemTypes {
		items[itemType], err = selectItems(hub, itemType, nil, !all)
		if err != nil {
			return err
		}
	}

	err = listItems(hub, color.Output, cwhub.ItemTypes, items)
	if err != nil {
		return err
	}

	return nil
}

func NewHubListCmd() *cobra.Command {
	cmdHubList := &cobra.Command{
		Use:               "list [-a]",
		Short:             "List all installed configurations",
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE:              runHubList,
	}

	flags := cmdHubList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdHubList
}

func runHubUpdate(cmd *cobra.Command, args []string) error {
	local := csConfig.Hub
	remote := require.RemoteHub(csConfig)

	// don't use require.Hub because if there is no index file, it would fail
	hub, err := cwhub.NewHub(local, remote, true)
	if err != nil {
		return fmt.Errorf("failed to update hub: %w", err)
	}

	for _, v := range hub.Warnings {
		log.Info(v)
	}

	return nil
}

func NewHubUpdateCmd() *cobra.Command {
	cmdHubUpdate := &cobra.Command{
		Use:   "update",
		Short: "Download the latest index (catalog of available configurations)",
		Long: `
Fetches the .index.json file from the hub, containing the list of available configs.
`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE:              runHubUpdate,
	}

	return cmdHubUpdate
}

func runHubUpgrade(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	force, err := flags.GetBool("force")
	if err != nil {
		return err
	}

	hub, err := require.Hub(csConfig, require.RemoteHub(csConfig))
	if err != nil {
		return err
	}

	for _, itemType := range cwhub.ItemTypes {
		items, err := hub.GetInstalledItems(itemType)
		if err != nil {
			return err
		}

		updated := 0

		log.Infof("Upgrading %s", itemType)
		for _, item := range items {
			didUpdate, err := item.Upgrade(force)
			if err != nil {
				return err
			}
			if didUpdate {
				updated++
			}
		}
		log.Infof("Upgraded %d %s", updated, itemType)
	}

	return nil
}

func NewHubUpgradeCmd() *cobra.Command {
	cmdHubUpgrade := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade all configurations to their latest version",
		Long: `
Upgrade all configs installed from Crowdsec Hub. Run 'sudo cscli hub update' if you want the latest versions available.
`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE:              runHubUpgrade,
	}

	flags := cmdHubUpgrade.Flags()
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmdHubUpgrade
}
