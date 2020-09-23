package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

func NewScenarioCmd() *cobra.Command {
	var cmdScenario = &cobra.Command{
		Use:   "scenario [action] [config]",
		Short: "Install/Remove/Upgrade/Inspect scenario(s) from hub",
		Long: `
		Install/Remove/Upgrade/Inspect scenario(s) from the CrowdSec Hub.

In order to download latest versions of configuration, 
you should [update cscli](./cscli_update.md).

[action] must be install/upgrade or remove.

[config_name] must be a valid config name from [Crowdsec Hub](https://hub.crowdsec.net).
`,
		Example: `cscli scenario [action] [config_name]`,
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

	var cmdScenarioInstall = &cobra.Command{
		Use:     "scenario [config]",
		Short:   "Install given scenario",
		Long:    `Fetch and install given scenario from hub`,
		Example: `cscli scenario install crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			for _, name := range args {
				InstallItem(name, cwhub.SCENARIOS)
			}
		},
	}
	cmdScenarioInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdScenarioInstall.PersistentFlags().BoolVar(&forceInstall, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdScenario.AddCommand(cmdScenarioInstall)

	var cmdScenarioRemove = &cobra.Command{
		Use:     "remove [config]",
		Short:   "Remove given scenario",
		Long:    `remove given scenario`,
		Example: `cscli scenario remove crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}

			if removeAll {
				RemoveMany(cwhub.SCENARIOS, "")
			} else {
				for _, name := range args {
					RemoveMany(cwhub.SCENARIOS, name)
				}
			}
		},
	}
	cmdScenarioRemove.PersistentFlags().BoolVar(&purgeRemove, "purge", false, "Delete source file in ~/.cscli/hub/ too")
	cmdScenarioRemove.PersistentFlags().BoolVar(&removeAll, "all", false, "Delete all the files in selected scope")
	cmdScenario.AddCommand(cmdScenarioRemove)

	var cmdScenarioUpgrade = &cobra.Command{
		Use:     "upgrade [config]",
		Short:   "Upgrade given scenario",
		Long:    `Fetch and Upgrade given scenario from hub`,
		Example: `cscli scenario upgrade crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if upgradeAll {
				UpgradeConfig(cwhub.SCENARIOS, "")
			} else {
				for _, name := range args {
					UpgradeConfig(cwhub.SCENARIOS, name)
				}
			}
		},
	}
	cmdScenarioUpgrade.PersistentFlags().BoolVarP(&upgradeAll, "download-only", "d", false, "Only download packages, don't enable")
	cmdScenarioUpgrade.PersistentFlags().BoolVar(&forceUpgrade, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdScenario.AddCommand(cmdScenarioUpgrade)

	var cmdScenarioInspect = &cobra.Command{
		Use:     "inspect [config]",
		Short:   "Inspect given scenario",
		Long:    `Inspect given scenario`,
		Example: `cscli scenario inspect crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			InspectItem(args[0], cwhub.SCENARIOS)
		},
	}
	cmdScenarioInspect.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "http://127.0.0.1:6060/metrics", "Prometheus url")
	cmdScenario.AddCommand(cmdScenarioInspect)

	var cmdScenarioList = &cobra.Command{
		Use:   "list [config]",
		Short: "List all scenario or given one",
		Long:  `List all scenario or given one`,
		Example: `cscli scenario list
cscli scenario list crowdsecurity/xxx`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			ListItem(cwhub.SCENARIOS, args)
		},
	}
	cmdScenario.AddCommand(cmdScenarioList)

	return cmdScenario
}
