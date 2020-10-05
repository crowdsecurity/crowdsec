package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

func NewParsersCmd() *cobra.Command {
	var cmdParsers = &cobra.Command{
		Use:   "parsers [action] [config]",
		Short: "Install/Remove/Upgrade/Inspect parser(s) from hub",
		Long: `
		Install/Remove/Upgrade/Inspect parser(s) from the CrowdSec Hub.

In order to download latest versions of configuration, 
you should [update cscli](./cscli_update.md).

[action] must be install/upgrade or remove.

[config_name] must be a valid config name from [Crowdsec Hub](https://hub.crowdsec.net).
`,
		Example: `cscli install [type] [config_name]`,
		Args:    cobra.MinimumNArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if csConfig.Cscli == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			if err := setHubBranch(); err != nil {
				return fmt.Errorf("error while setting hub branch: %s", err)
			}
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if cmd.Name() == "inspect" || cmd.Name() == "list" {
				return
			}
			log.Infof("Run 'systemctl reload crowdsec' for the new configuration to be effective.")
		},
	}
	cmdParsers.PersistentFlags().StringVarP(&cwhub.HubBranch, "branch", "b", "", "Use given branch from hub")

	var cmdParsersInstall = &cobra.Command{
		Use:     "install [config]",
		Short:   "Install given parser(s)",
		Long:    `Fetch and install given parser(s) from hub`,
		Example: `cscli parsers install crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			for _, name := range args {
				InstallItem(name, cwhub.PARSERS)
			}
		},
	}
	cmdParsersInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdParsersInstall.PersistentFlags().BoolVar(&forceInstall, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdParsers.AddCommand(cmdParsersInstall)

	var cmdParsersRemove = &cobra.Command{
		Use:     "remove [config]",
		Short:   "Remove given parser(s)",
		Long:    `Remove given parse(s) from hub`,
		Example: `cscli parsers remove crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}

			if removeAll {
				RemoveMany(cwhub.PARSERS, "")
			} else {
				for _, name := range args {
					RemoveMany(cwhub.PARSERS, name)
				}
			}
		},
	}
	cmdParsersRemove.PersistentFlags().BoolVar(&purgeRemove, "purge", false, "Delete source file in ~/.cscli/hub/ too")
	cmdParsersRemove.PersistentFlags().BoolVar(&removeAll, "all", false, "Delete all the files in selected scope")
	cmdParsers.AddCommand(cmdParsersRemove)

	var cmdParsersUpgrade = &cobra.Command{
		Use:     "upgrade [config]",
		Short:   "Upgrade given parser(s)",
		Long:    `Fetch and upgrade given parser(s) from hub`,
		Example: `cscli parsers upgrade crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if upgradeAll {
				UpgradeConfig(cwhub.PARSERS, "")
			} else {
				for _, name := range args {
					UpgradeConfig(cwhub.PARSERS, name)
				}
			}
		},
	}
	cmdParsersUpgrade.PersistentFlags().BoolVarP(&upgradeAll, "download-only", "d", false, "Only download packages, don't enable")
	cmdParsersUpgrade.PersistentFlags().BoolVar(&forceUpgrade, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdParsers.AddCommand(cmdParsersUpgrade)

	var cmdParsersInspect = &cobra.Command{
		Use:     "inspect [config]",
		Short:   "Inspect given parser",
		Long:    `Inspect given parser`,
		Example: `cscli parsers inspect crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			InspectItem(args[0], cwhub.PARSERS)
		},
	}
	cmdParsersInspect.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "http://127.0.0.1:6060/metrics", "Prometheus url")
	cmdParsers.AddCommand(cmdParsersInspect)

	var cmdParsersList = &cobra.Command{
		Use:   "list [config]",
		Short: "List all parsers or given one",
		Long:  `List all parsers or given one`,
		Example: `cscli parsers list
cscli parser list crowdsecurity/xxx`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			ListItem(cwhub.PARSERS, args)
		},
	}
	cmdParsersList.PersistentFlags().BoolVarP(&listAll, "all", "a", false, "List as well disabled items")
	cmdParsers.AddCommand(cmdParsersList)

	return cmdParsers
}
