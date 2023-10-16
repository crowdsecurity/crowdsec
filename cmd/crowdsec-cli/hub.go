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
	cmdHub.PersistentFlags().StringVarP(&cwhub.HubBranch, "branch", "b", "", "Use given branch from hub")

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

	if err = require.Hub(csConfig); err != nil {
		return err
	}

	// use LocalSync to get warnings about tainted / outdated items
	warn, _ := cwhub.LocalSync(csConfig.Hub)
	for _, v := range warn {
		log.Info(v)
	}

	cwhub.DisplaySummary()

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
		RunE: 	    runHubList,
	}

	flags := cmdHubList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdHubList
}

func runHubUpdate(cmd *cobra.Command, args []string) error {
	if err := csConfig.LoadHub(); err != nil {
		return err
	}

	if err := cwhub.UpdateHubIdx(csConfig.Hub); err != nil {
		if !errors.Is(err, cwhub.ErrIndexNotFound) {
			return fmt.Errorf("failed to get Hub index : %w", err)
		}
		log.Warnf("Could not find index file for branch '%s', using 'master'", cwhub.HubBranch)
		cwhub.HubBranch = "master"
		if err := cwhub.UpdateHubIdx(csConfig.Hub); err != nil {
			return fmt.Errorf("failed to get Hub index after retry: %w", err)
		}
	}

	// use LocalSync to get warnings about tainted / outdated items
	warn, _ := cwhub.LocalSync(csConfig.Hub)
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

			cwhub.SetHubBranch()

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

	if err := require.Hub(csConfig); err != nil {
		return err
	}

	log.Infof("Upgrading collections")
	if err := cwhub.UpgradeConfig(csConfig, cwhub.COLLECTIONS, "", force); err != nil {
		return err
	}

	log.Infof("Upgrading parsers")
	if err := cwhub.UpgradeConfig(csConfig, cwhub.PARSERS, "", force); err != nil {
		return err
	}

	log.Infof("Upgrading scenarios")
	if err := cwhub.UpgradeConfig(csConfig, cwhub.SCENARIOS, "", force); err != nil {
		return err
	}

	log.Infof("Upgrading postoverflows")
	if err := cwhub.UpgradeConfig(csConfig, cwhub.POSTOVERFLOWS, "", force); err != nil {
		return err
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

			cwhub.SetHubBranch()

			return nil
		},
		RunE: runHubUpgrade,
	}

	flags := cmdHubUpgrade.Flags()
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmdHubUpgrade
}
