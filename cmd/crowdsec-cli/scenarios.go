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
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"scenario"},
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadHub(); err != nil {
				log.Fatalf(err.Error())
			}
			if csConfig.Hub == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			if err := setHubBranch(); err != nil {
				return fmt.Errorf("error while setting hub branch: %s", err)
			}

			if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
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

	var ignoreError bool
	var cmdScenariosInstall = &cobra.Command{
		Use:     "install [config]",
		Short:   "Install given scenario(s)",
		Long:    `Fetch and install given scenario(s) from hub`,
		Example: `cscli scenarios install crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if err := LoadHub(); err != nil {
				return nil, cobra.ShellCompDirectiveDefault
			}
			upstreamScenario := make([]string, 0)
			hubItems := cwhub.GetHubStatusForItemType(cwhub.SCENARIOS, "", true)
			for _, item := range hubItems {
				upstreamScenario = append(upstreamScenario, item.Name)
			}
			cobra.CompDebugln(fmt.Sprintf("scenarios: %+v", upstreamScenario), true)
			return upstreamScenario, cobra.ShellCompDirectiveNoFileComp
		},
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			for _, name := range args {
				if err := cwhub.InstallItem(csConfig, name, cwhub.SCENARIOS, forceAction, downloadOnly); err != nil {
					if ignoreError {
						log.Errorf("Error while installing '%s': %s", name, err)
					} else {
						log.Fatalf("Error while installing '%s': %s", name, err)
					}
				}
			}
		},
	}
	cmdScenariosInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdScenariosInstall.PersistentFlags().BoolVar(&forceAction, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdScenariosInstall.PersistentFlags().BoolVar(&ignoreError, "ignore", false, "Ignore errors when installing multiple scenarios")
	cmdScenarios.AddCommand(cmdScenariosInstall)

	var cmdScenariosRemove = &cobra.Command{
		Use:     "remove [config]",
		Short:   "Remove given scenario(s)",
		Long:    `remove given scenario(s)`,
		Example: `cscli scenarios remove crowdsec/xxx crowdsec/xyz`,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if err := LoadHub(); err != nil {
				return nil, cobra.ShellCompDirectiveDefault
			}
			installedScenario, err := cwhub.GetInstalledScenariosAsString()
			if err != nil {
				cobra.CompDebugln(fmt.Sprintf("list installed scenarios err: %s", err), true)
				return nil, cobra.ShellCompDirectiveDefault
			}
			cobra.CompDebugln(fmt.Sprintf("scenarios: %+v", installedScenario), true)
			return installedScenario, cobra.ShellCompDirectiveNoFileComp
		},
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if all {
				cwhub.RemoveMany(csConfig, cwhub.SCENARIOS, "", all, purge, forceAction)
				return
			}

			if len(args) == 0 {
				log.Fatalf("Specify at least one scenario to remove or '--all' flag.")
			}

			for _, name := range args {
				cwhub.RemoveMany(csConfig, cwhub.SCENARIOS, name, all, purge, forceAction)
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
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if err := LoadHub(); err != nil {
				return nil, cobra.ShellCompDirectiveDefault
			}
			installedScenario, err := cwhub.GetInstalledScenariosAsString()
			if err != nil {
				cobra.CompDebugln(fmt.Sprintf("list installed scenarios err: %s", err), true)
				return nil, cobra.ShellCompDirectiveDefault
			}
			cobra.CompDebugln(fmt.Sprintf("scenarios: %+v", installedScenario), true)
			return installedScenario, cobra.ShellCompDirectiveNoFileComp
		},
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if all {
				cwhub.UpgradeConfig(csConfig, cwhub.SCENARIOS, "", forceAction)
			} else {
				if len(args) == 0 {
					log.Fatalf("no target scenario to upgrade")
				}
				for _, name := range args {
					cwhub.UpgradeConfig(csConfig, cwhub.SCENARIOS, name, forceAction)
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
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if err := LoadHub(); err != nil {
				return nil, cobra.ShellCompDirectiveDefault
			}
			installedScenario, err := cwhub.GetInstalledScenariosAsString()
			if err != nil {
				cobra.CompDebugln(fmt.Sprintf("list installed scenarios err: %s", err), true)
				return nil, cobra.ShellCompDirectiveDefault
			}
			cobra.CompDebugln(fmt.Sprintf("scenarios: %+v", installedScenario), true)
			return installedScenario, cobra.ShellCompDirectiveNoFileComp
		},
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
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
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			ListItems([]string{cwhub.SCENARIOS}, args, false, true, all)
		},
	}
	cmdScenariosList.PersistentFlags().BoolVarP(&all, "all", "a", false, "List disabled items as well")
	cmdScenarios.AddCommand(cmdScenariosList)

	return cmdScenarios
}
