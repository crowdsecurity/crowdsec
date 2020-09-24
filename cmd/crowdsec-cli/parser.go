package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

func NewParserCmd() *cobra.Command {
	var cmdParser = &cobra.Command{
		Use:   "parser [action] [config]",
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

	var cmdParserInstall = &cobra.Command{
		Use:     "install [config]",
		Short:   "Install given parser",
		Long:    `Fetch and install given parser from hub`,
		Example: `cscli parser install crowdsec/xxx`,
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
	cmdParserInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdParserInstall.PersistentFlags().BoolVar(&forceInstall, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdParser.AddCommand(cmdParserInstall)

	var cmdParserRemove = &cobra.Command{
		Use:     "remove [config]",
		Short:   "Remove given parser",
		Long:    `Remove given parser from hub`,
		Example: `cscli parser remove crowdsec/xxx`,
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
	cmdParserRemove.PersistentFlags().BoolVar(&purgeRemove, "purge", false, "Delete source file in ~/.cscli/hub/ too")
	cmdParserRemove.PersistentFlags().BoolVar(&removeAll, "all", false, "Delete all the files in selected scope")
	cmdParser.AddCommand(cmdParserRemove)

	var cmdParserUpgrade = &cobra.Command{
		Use:     "upgrade [config]",
		Short:   "Upgrade given parser",
		Long:    `Fetch and upgrade given parser from hub`,
		Example: `cscli parser upgrade crowdsec/xxx`,
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
	cmdParserUpgrade.PersistentFlags().BoolVarP(&upgradeAll, "download-only", "d", false, "Only download packages, don't enable")
	cmdParserUpgrade.PersistentFlags().BoolVar(&forceUpgrade, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdParser.AddCommand(cmdParserUpgrade)

	var cmdParserInspect = &cobra.Command{
		Use:     "inspect [config]",
		Short:   "Inspect given parser",
		Long:    `Inspect given parser`,
		Example: `cscli parser inspect crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			InspectItem(args[0], cwhub.PARSERS)
		},
	}
	cmdParserInspect.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "http://127.0.0.1:6060/metrics", "Prometheus url")
	cmdParser.AddCommand(cmdParserInspect)

	var cmdParserList = &cobra.Command{
		Use:   "list [config]",
		Short: "List all parser or given one",
		Long:  `List all parser or given one`,
		Example: `cscli parser list
cscli parser list crowdsecurity/xxx`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			ListItem(cwhub.PARSERS, args)
		},
	}
	cmdParser.AddCommand(cmdParserList)

	return cmdParser
}
