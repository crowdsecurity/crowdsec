package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
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
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"scenario"},
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadHub(); err != nil {
				return err
			}
			if csConfig.Hub == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			if err := cwhub.SetHubBranch(); err != nil {
				return fmt.Errorf("while setting hub branch: %w", err)
			}

			if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Info("Run 'sudo cscli hub update' to get the hub index")
				return fmt.Errorf("failed to get hub index: %w", err)
			}

			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if cmd.Name() == "inspect" || cmd.Name() == "list" {
				return
			}
			log.Infof(ReloadMessage())
		},
	}

	cmdScenarios.AddCommand(NewCmdScenariosInstall())
	cmdScenarios.AddCommand(NewCmdScenariosRemove())
	cmdScenarios.AddCommand(NewCmdScenariosUpgrade())
	cmdScenarios.AddCommand(NewCmdScenariosInspect())
	cmdScenarios.AddCommand(NewCmdScenariosList())

	return cmdScenarios
}

func NewCmdScenariosInstall() *cobra.Command {
	var ignoreError bool

	var cmdScenariosInstall = &cobra.Command{
		Use:     "install [config]",
		Short:   "Install given scenario(s)",
		Long:    `Fetch and install given scenario(s) from hub`,
		Example: `cscli scenarios install crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.SCENARIOS, args, toComplete)
		},
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, name := range args {
				t := cwhub.GetItem(cwhub.SCENARIOS, name)
				if t == nil {
					nearestItem, score := GetDistance(cwhub.SCENARIOS, name)
					Suggest(cwhub.SCENARIOS, name, nearestItem.Name, score, ignoreError)
					continue
				}
				if err := cwhub.InstallItem(csConfig, name, cwhub.SCENARIOS, forceAction, downloadOnly); err != nil {
					if !ignoreError {
						return fmt.Errorf("error while installing '%s': %w", name, err)
					}
					log.Errorf("Error while installing '%s': %s", name, err)
				}
			}
			return nil
		},
	}
	cmdScenariosInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdScenariosInstall.PersistentFlags().BoolVar(&forceAction, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdScenariosInstall.PersistentFlags().BoolVar(&ignoreError, "ignore", false, "Ignore errors when installing multiple scenarios")

	return cmdScenariosInstall
}

func NewCmdScenariosRemove() *cobra.Command {
	var cmdScenariosRemove = &cobra.Command{
		Use:     "remove [config]",
		Short:   "Remove given scenario(s)",
		Long:    `remove given scenario(s)`,
		Example: `cscli scenarios remove crowdsec/xxx crowdsec/xyz`,
		Aliases: []string{"delete"},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.SCENARIOS, args, toComplete)
		},
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				cwhub.RemoveMany(csConfig, cwhub.SCENARIOS, "", all, purge, forceAction)
				return nil
			}

			if len(args) == 0 {
				return fmt.Errorf("specify at least one scenario to remove or '--all'")
			}

			for _, name := range args {
				cwhub.RemoveMany(csConfig, cwhub.SCENARIOS, name, all, purge, forceAction)
			}
			return nil
		},
	}
	cmdScenariosRemove.PersistentFlags().BoolVar(&purge, "purge", false, "Delete source file too")
	cmdScenariosRemove.PersistentFlags().BoolVar(&forceAction, "force", false, "Force remove : Remove tainted and outdated files")
	cmdScenariosRemove.PersistentFlags().BoolVar(&all, "all", false, "Delete all the scenarios")

	return cmdScenariosRemove
}

func NewCmdScenariosUpgrade() *cobra.Command {
	var cmdScenariosUpgrade = &cobra.Command{
		Use:     "upgrade [config]",
		Short:   "Upgrade given scenario(s)",
		Long:    `Fetch and Upgrade given scenario(s) from hub`,
		Example: `cscli scenarios upgrade crowdsec/xxx crowdsec/xyz`,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.SCENARIOS, args, toComplete)
		},
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				cwhub.UpgradeConfig(csConfig, cwhub.SCENARIOS, "", forceAction)
			} else {
				if len(args) == 0 {
					return fmt.Errorf("specify at least one scenario to upgrade or '--all'")
				}
				for _, name := range args {
					cwhub.UpgradeConfig(csConfig, cwhub.SCENARIOS, name, forceAction)
				}
			}
			return nil
		},
	}
	cmdScenariosUpgrade.PersistentFlags().BoolVarP(&all, "all", "a", false, "Upgrade all the scenarios")
	cmdScenariosUpgrade.PersistentFlags().BoolVar(&forceAction, "force", false, "Force upgrade : Overwrite tainted and outdated files")

	return cmdScenariosUpgrade
}

func NewCmdScenariosInspect() *cobra.Command {
	var cmdScenariosInspect = &cobra.Command{
		Use:     "inspect [config]",
		Short:   "Inspect given scenario",
		Long:    `Inspect given scenario`,
		Example: `cscli scenarios inspect crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.SCENARIOS, args, toComplete)
		},
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			InspectItem(args[0], cwhub.SCENARIOS)
		},
	}
	cmdScenariosInspect.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "", "Prometheus url")

	return cmdScenariosInspect
}

func NewCmdScenariosList() *cobra.Command {
	var cmdScenariosList = &cobra.Command{
		Use:   "list [config]",
		Short: "List all scenario(s) or given one",
		Long:  `List all scenario(s) or given one`,
		Example: `cscli scenarios list
cscli scenarios list crowdsecurity/xxx`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			ListItems(color.Output, []string{cwhub.SCENARIOS}, args, false, true, all)
		},
	}
	cmdScenariosList.PersistentFlags().BoolVarP(&all, "all", "a", false, "List disabled items as well")

	return cmdScenariosList
}
