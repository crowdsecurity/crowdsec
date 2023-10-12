package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewScenariosCmd() *cobra.Command {
	cmdScenarios := &cobra.Command{
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
			if err := require.Hub(csConfig); err != nil {
				return err
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

func runScenariosInstall(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	downloadOnly, err := flags.GetBool("download-only")
	if err != nil {
		return err
	}

	force, err := flags.GetBool("force")
	if err != nil {
		return err
	}

	ignoreError, err := flags.GetBool("ignore")
	if err != nil {
		return err
	}

	for _, name := range args {
		t := cwhub.GetItem(cwhub.SCENARIOS, name)
		if t == nil {
			nearestItem, score := GetDistance(cwhub.SCENARIOS, name)
			Suggest(cwhub.SCENARIOS, name, nearestItem.Name, score, ignoreError)

			continue
		}

		if err := cwhub.InstallItem(csConfig, name, cwhub.SCENARIOS, force, downloadOnly); err != nil {
			if !ignoreError {
				return fmt.Errorf("error while installing '%s': %w", name, err)
			}
			log.Errorf("Error while installing '%s': %s", name, err)
		}
	}

	return nil
}

func NewCmdScenariosInstall() *cobra.Command {
	cmdScenariosInstall := &cobra.Command{
		Use:               "install [config]",
		Short:             "Install given scenario(s)",
		Long:              `Fetch and install given scenario(s) from hub`,
		Example:           `cscli scenarios install crowdsec/xxx crowdsec/xyz`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.SCENARIOS, args, toComplete)
		},
		RunE: runScenariosInstall,
	}

	flags := cmdScenariosInstall.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install : Overwrite tainted and outdated files")
	flags.Bool("ignore", false, "Ignore errors when installing multiple scenarios")

	return cmdScenariosInstall
}

func runScenariosRemove(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	purge, err := flags.GetBool("purge")
	if err != nil {
		return err
	}

	force, err := flags.GetBool("force")
	if err != nil {
		return err
	}

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	if all {
		err := cwhub.RemoveMany(csConfig, cwhub.SCENARIOS, "", all, purge, force)
		if err != nil {
			return err
		}

		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one scenario to remove or '--all'")
	}

	for _, name := range args {
		err := cwhub.RemoveMany(csConfig, cwhub.SCENARIOS, name, all, purge, force)
		if err != nil {
			return err
		}
	}

	return nil
}

func NewCmdScenariosRemove() *cobra.Command {
	cmdScenariosRemove := &cobra.Command{
		Use:               "remove [config]",
		Short:             "Remove given scenario(s)",
		Long:              `remove given scenario(s)`,
		Example:           `cscli scenarios remove crowdsec/xxx crowdsec/xyz`,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.SCENARIOS, args, toComplete)
		},
		RunE: runScenariosRemove,
	}

	flags := cmdScenariosRemove.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove: Remove tainted and outdated files")
	flags.Bool("all", false, "Delete all the scenarios")

	return cmdScenariosRemove
}

func runScenariosUpgrade(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	force, err := flags.GetBool("force")
	if err != nil {
		return err
	}

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	if all {
		cwhub.UpgradeConfig(csConfig, cwhub.SCENARIOS, "", force)
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one scenario to upgrade or '--all'")
	}

	for _, name := range args {
		cwhub.UpgradeConfig(csConfig, cwhub.SCENARIOS, name, force)
	}

	return nil
}

func NewCmdScenariosUpgrade() *cobra.Command {
	cmdScenariosUpgrade := &cobra.Command{
		Use:               "upgrade [config]",
		Short:             "Upgrade given scenario(s)",
		Long:              `Fetch and Upgrade given scenario(s) from hub`,
		Example:           `cscli scenarios upgrade crowdsec/xxx crowdsec/xyz`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.SCENARIOS, args, toComplete)
		},
		RunE: runScenariosUpgrade,
	}

	flags := cmdScenariosUpgrade.Flags()
	flags.BoolP("all", "a", false, "Upgrade all the scenarios")
	flags.Bool("force", false, "Force upgrade : Overwrite tainted and outdated files")

	return cmdScenariosUpgrade
}

func runScenariosInspect(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	var err error
	// XXX: set global
	prometheusURL, err = flags.GetString("url")
	if err != nil {
		return err
	}

	InspectItem(args[0], cwhub.SCENARIOS)

	return nil
}

func NewCmdScenariosInspect() *cobra.Command {
	cmdScenariosInspect := &cobra.Command{
		Use:               "inspect [config]",
		Short:             "Inspect given scenario",
		Long:              `Inspect given scenario`,
		Example:           `cscli scenarios inspect crowdsec/xxx`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.SCENARIOS, args, toComplete)
		},
		RunE: runScenariosInspect,
	}

	flags := cmdScenariosInspect.Flags()
	flags.StringP("url", "u", "", "Prometheus url")

	return cmdScenariosInspect
}

func runScenariosList(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	// XXX: will happily ignore missing scenarios
	ListItems(color.Output, []string{cwhub.SCENARIOS}, args, false, true, all)

	return nil
}

func NewCmdScenariosList() *cobra.Command {
	cmdScenariosList := &cobra.Command{
		Use:   "list [config]",
		Short: "List all scenario(s) or given one",
		Long:  `List all scenario(s) or given one`,
		Example: `cscli scenarios list
cscli scenarios list crowdsecurity/xxx`,
		DisableAutoGenTag: true,
		RunE:              runScenariosList,
	}

	flags := cmdScenariosList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdScenariosList
}
