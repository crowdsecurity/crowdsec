package main

import (
	"errors"
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

const (
	hubURLTemplate  = "https://hub-cdn.crowdsec.net/%s/%s"
	remoteIndexPath = ".index.json"
)

var hubBranch = ""

func NewHubCmd() *cobra.Command {
	var cmdHub = &cobra.Command{
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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if csConfig.Cscli == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			return nil
		},
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

	hub, err := require.Hub(csConfig)
	if err != nil {
		return err
	}

	// use LocalSync to get warnings about tainted / outdated items
	warn, _ := hub.LocalSync()
	for _, v := range warn {
		log.Info(v)
	}

	for line := range hub.ItemStats() {
		log.Info(line)
	}

	err = ListItems(color.Output, []string{
		cwhub.COLLECTIONS, cwhub.PARSERS, cwhub.SCENARIOS, cwhub.POSTOVERFLOWS,
	}, nil, true, false, all)
	if err != nil {
		return err
	}

	return nil
}

func NewHubListCmd() *cobra.Command {
	var cmdHubList = &cobra.Command{
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
	// don't use require.Hub because if there is no index file, it would fail

	branch := hubBranch
	if branch == "" {
		branch = chooseHubBranch()
	}

	log.Debugf("Using branch '%s' for the hub", branch)

	hub, err := cwhub.InitHubUpdate(csConfig.Hub, hubURLTemplate, branch, remoteIndexPath)
	if err != nil {
		if !errors.Is(err, cwhub.ErrIndexNotFound) {
			return fmt.Errorf("failed to get Hub index : %w", err)
		}
		log.Warnf("Could not find index file for branch '%s', using 'master'", branch)
		branch = "master"
		if hub, err = cwhub.InitHubUpdate(csConfig.Hub, hubURLTemplate, branch, remoteIndexPath); err != nil {
			return fmt.Errorf("failed to get Hub index after retry: %w", err)
		}
	}

	// use LocalSync to get warnings about tainted / outdated items
	warn, _ := hub.LocalSync()
	for _, v := range warn {
		log.Info(v)
	}

	return nil
}

func NewHubUpdateCmd() *cobra.Command {
	var cmdHubUpdate = &cobra.Command{
		Use:   "update",
		Short: "Download the latest index (catalog of available configurations)",
		Long: `
Fetches the [.index.json](https://github.com/crowdsecurity/hub/blob/master/.index.json) file from hub, containing the list of available configs.
`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if csConfig.Cscli == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			return nil
		},
		RunE: runHubUpdate,
	}

	return cmdHubUpdate
}

func runHubUpgrade(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	force, err := flags.GetBool("force")
	if err != nil {
		return err
	}

	branch := hubBranch
	if branch == "" {
		branch = chooseHubBranch()
	}

	log.Debugf("Using branch '%s' for the hub", branch)

	hub, err := require.Hub(csConfig)
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
			didUpdate, err := hub.UpgradeItem(itemType, item.Name, force, hubURLTemplate, branch)
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
	var cmdHubUpgrade = &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade all configurations to their latest version",
		Long: `
Upgrade all configs installed from Crowdsec Hub. Run 'sudo cscli hub update' if you want the latest versions available.
`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if csConfig.Cscli == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			return nil
		},
		RunE: runHubUpgrade,
	}

	flags := cmdHubUpgrade.Flags()
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmdHubUpgrade
}
