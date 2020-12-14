package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

func NewScenariosCmd() *cobra.Command {
	var cmdScenarios = &cobra.Command{
		Use:   "scenarios [action] [config]",
		Short: "Install/Remove/Upgrade/Inspect scenario(s) from hub",
		Example: `cscli scenarios list [-a]
cscli scenarios install crowdsecurity/ssh-bf
cscli scenarios inspect crowdsecurity/ssh-bf
cscli scenarios upgrade crowdsecurity/ssh-bf
cscli scenarios remove crowdsecurity/ssh-bf
`,
		Args: cobra.MinimumNArgs(1),
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
			log.Infof("Run 'sudo systemctl reload crowdsec' for the new configuration to be effective.")
		},
	}

	var cmdScenariosInstall = &cobra.Command{
		Use:     "install [config]",
		Short:   "Install given scenario(s)",
		Long:    `Fetch and install given scenario(s) from hub`,
		Example: `cscli scenarios install crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}
			for _, name := range args {
				InstallItem(name, cwhub.SCENARIOS, forceAction)
			}
		},
	}
	cmdScenariosInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdScenariosInstall.PersistentFlags().BoolVar(&forceAction, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdScenarios.AddCommand(cmdScenariosInstall)

	var cmdScenariosRemove = &cobra.Command{
		Use:     "remove [config]",
		Short:   "Remove given scenario(s)",
		Long:    `remove given scenario(s)`,
		Example: `cscli scenarios remove crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}

			if all {
				RemoveMany(cwhub.SCENARIOS, "")
			} else {
				for _, name := range args {
					RemoveMany(cwhub.SCENARIOS, name)
				}
			}
		},
	}
	cmdScenariosRemove.PersistentFlags().BoolVar(&purge, "purge", false, "Delete source file too")
	cmdScenariosRemove.PersistentFlags().BoolVar(&forceAction, "force", false, "Force remove : Remove tainted and outdated files")
	cmdScenariosRemove.PersistentFlags().BoolVar(&all, "all", false, "Delete all the scenarios")
	cmdScenarios.AddCommand(cmdScenariosRemove)

	var cmdScenariosUpgrade = &cobra.Command{
		Use:     "upgrade [config]",
		Short:   "Upgrade given scenario(s)",
		Long:    `Fetch and Upgrade given scenario(s) from hub`,
		Example: `cscli scenarios upgrade crowdsec/xxx crowdsec/xyz`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}
			if all {
				UpgradeConfig(cwhub.SCENARIOS, "", forceAction)
			} else {
				for _, name := range args {
					UpgradeConfig(cwhub.SCENARIOS, name, forceAction)
				}
			}
		},
	}
	cmdScenariosUpgrade.PersistentFlags().BoolVarP(&all, "all", "a", false, "Upgrade all the scenarios")
	cmdScenariosUpgrade.PersistentFlags().BoolVar(&forceAction, "force", false, "Force upgrade : Overwrite tainted and outdated files")
	cmdScenarios.AddCommand(cmdScenariosUpgrade)

	var cmdScenariosInspect = &cobra.Command{
		Use:     "inspect [config]",
		Short:   "Inspect given scenario",
		Long:    `Inspect given scenario`,
		Example: `cscli scenarios inspect crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}
			InspectItem(args[0], cwhub.SCENARIOS)
		},
	}
	cmdScenariosInspect.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "", "Prometheus url")
	cmdScenarios.AddCommand(cmdScenariosInspect)

	var cmdScenariosList = &cobra.Command{
		Use:   "list [config]",
		Short: "List all scenario(s) or given one",
		Long:  `List all scenario(s) or given one`,
		Example: `cscli scenarios list
cscli scenarios list crowdsecurity/xxx`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}
			ListItem(cwhub.SCENARIOS, args)
		},
	}
	cmdScenariosList.PersistentFlags().BoolVarP(&all, "all", "a", false, "List as well disabled items")
	cmdScenarios.AddCommand(cmdScenariosList)

	return cmdScenarios
}
