package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewParsersCmd() *cobra.Command {
	cmdParsers := &cobra.Command{
		Use:   "parsers [action] [config]",
		Short: "Install/Remove/Upgrade/Inspect parser(s) from hub",
		Example: `cscli parsers install crowdsecurity/sshd-logs
cscli parsers inspect crowdsecurity/sshd-logs
cscli parsers upgrade crowdsecurity/sshd-logs
cscli parsers list
cscli parsers remove crowdsecurity/sshd-logs
`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"parser"},
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

	cmdParsers.AddCommand(NewParsersInstallCmd())
	cmdParsers.AddCommand(NewParsersRemoveCmd())
	cmdParsers.AddCommand(NewParsersUpgradeCmd())
	cmdParsers.AddCommand(NewParsersInspectCmd())
	cmdParsers.AddCommand(NewParsersListCmd())

	return cmdParsers
}

func runParsersInstall(cmd *cobra.Command, args []string) error {
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
		t := cwhub.GetItem(cwhub.PARSERS, name)
		if t == nil {
			nearestItem, score := GetDistance(cwhub.PARSERS, name)
			Suggest(cwhub.PARSERS, name, nearestItem.Name, score, ignoreError)

			continue
		}

		if err := cwhub.InstallItem(csConfig, name, cwhub.PARSERS, force, downloadOnly); err != nil {
			if !ignoreError {
				return fmt.Errorf("error while installing '%s': %w", name, err)
			}
			log.Errorf("Error while installing '%s': %s", name, err)
		}
	}

	return nil
}

func NewParsersInstallCmd() *cobra.Command {
	cmdParsersInstall := &cobra.Command{
		Use:               "install [config]",
		Short:             "Install given parser(s)",
		Long:              `Fetch and install given parser(s) from hub`,
		Example:           `cscli parsers install crowdsec/xxx crowdsec/xyz`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.PARSERS, args, toComplete)
		},
		RunE: runParsersInstall,
	}

	flags := cmdParsersInstall.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install: Overwrite tainted and outdated files")
	flags.Bool("ignore", false, "Ignore errors when installing multiple parsers")

	return cmdParsersInstall
}

func runParsersRemove(cmd *cobra.Command, args []string) error {
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
		err := cwhub.RemoveMany(csConfig, cwhub.PARSERS, "", all, purge, force)
		if err != nil {
			return err
		}

		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one parser to remove or '--all'")
	}

	for _, name := range args {
		err := cwhub.RemoveMany(csConfig, cwhub.PARSERS, name, all, purge, force)
		if err != nil {
			return err
		}
	}

	return nil
}

func NewParsersRemoveCmd() *cobra.Command {
	cmdParsersRemove := &cobra.Command{
		Use:               "remove [config]",
		Short:             "Remove given parser(s)",
		Long:              `Remove given parse(s) from hub`,
		Example:           `cscli parsers remove crowdsec/xxx crowdsec/xyz`,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS, args, toComplete)
		},
		RunE: runParsersRemove,
	}

	flags := cmdParsersRemove.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove: Remove tainted and outdated files")
	flags.Bool("all", false, "Delete all the parsers")

	return cmdParsersRemove
}

func runParsersUpgrade(cmd *cobra.Command, args []string) error {
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
		cwhub.UpgradeConfig(csConfig, cwhub.PARSERS, "", force)
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one parser to upgrade or '--all'")
	}

	for _, name := range args {
		cwhub.UpgradeConfig(csConfig, cwhub.PARSERS, name, force)
	}

	return nil
}

func NewParsersUpgradeCmd() *cobra.Command {
	cmdParsersUpgrade := &cobra.Command{
		Use:               "upgrade [config]",
		Short:             "Upgrade given parser(s)",
		Long:              `Fetch and upgrade given parser(s) from hub`,
		Example:           `cscli parsers upgrade crowdsec/xxx crowdsec/xyz`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS, args, toComplete)
		},
		RunE: runParsersUpgrade,
	}

	flags := cmdParsersUpgrade.Flags()
	flags.Bool("all", false, "Upgrade all the parsers")
	flags.Bool("force", false, "Force upgrade : Overwrite tainted and outdated files")

	return cmdParsersUpgrade
}

func runParsersInspect(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	url, err := flags.GetString("url")
	if err != nil {
		return err
	}

	if url != "" {
		csConfig.Cscli.PrometheusUrl = url
	}

	InspectItem(args[0], cwhub.PARSERS)

	return nil
}

func NewParsersInspectCmd() *cobra.Command {
	cmdParsersInspect := &cobra.Command{
		Use:               "inspect [name]",
		Short:             "Inspect given parser",
		Long:              `Inspect given parser`,
		Example:           `cscli parsers inspect crowdsec/xxx`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS, args, toComplete)
		},
		RunE: runParsersInspect,
	}

	flags := cmdParsersInspect.Flags()
	flags.StringP("url", "u", "", "Prometheus url")

	return cmdParsersInspect
}

func runParsersList(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	// XXX: will happily ignore missing parsers
	ListItems(color.Output, []string{cwhub.PARSERS}, args, false, true, all)

	return nil
}

func NewParsersListCmd() *cobra.Command {
	cmdParsersList := &cobra.Command{
		Use:   "list [name]",
		Short: "List all parsers or given one",
		Long:  `List all parsers or given one`,
		Example: `cscli parsers list
cscli parser list crowdsecurity/xxx`,
		DisableAutoGenTag: true,
		RunE:              runParsersList,
	}

	flags := cmdParsersList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdParsersList
}
