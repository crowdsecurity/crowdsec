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
		Use:   "parsers <action> [parser]...",
		Short: "Manage hub parsers",
		Example: `cscli parsers list -a
cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs
cscli parsers inspect crowdsecurity/caddy-logs crowdsecurity/sshd-logs
cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs
cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs
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
		Use:               "install <parser>...",
		Short:             "Install given parser(s)",
		Long:              `Fetch and install one or more parsers from the hub`,
		Example:           `cscli parsers install crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.PARSERS, args, toComplete)
		},
		RunE: runParsersInstall,
	}

	flags := cmdParsersInstall.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install: overwrite tainted and outdated files")
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
		Use:               "remove <parser>...",
		Short:             "Remove given parser(s)",
		Long:              `Remove one or more parsers`,
		Example:           `cscli parsers remove crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS, args, toComplete)
		},
		RunE: runParsersRemove,
	}

	flags := cmdParsersRemove.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove: remove tainted and outdated files")
	flags.Bool("all", false, "Remove all the parsers")

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
		if err := cwhub.UpgradeConfig(csConfig, cwhub.PARSERS, "", force); err != nil {
			return err
		}
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one parser to upgrade or '--all'")
	}

	for _, name := range args {
		if err := cwhub.UpgradeConfig(csConfig, cwhub.PARSERS, name, force); err != nil {
			return err
		}
	}

	return nil
}

func NewParsersUpgradeCmd() *cobra.Command {
	cmdParsersUpgrade := &cobra.Command{
		Use:               "upgrade <parser>...",
		Short:             "Upgrade given parser(s)",
		Long:              `Fetch and upgrade one or more parsers from the hub`,
		Example:           `cscli parsers upgrade crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS, args, toComplete)
		},
		RunE: runParsersUpgrade,
	}

	flags := cmdParsersUpgrade.Flags()
	flags.BoolP("all", "a", false, "Upgrade all the parsers")
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmdParsersUpgrade
}

func runParsersInspect(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	var err error
	// XXX: set global
	prometheusURL, err = flags.GetString("url")
	if err != nil {
		return err
	}

	noMetrics, err := flags.GetBool("no-metrics")
	if err != nil {
		return err
	}

	for _, name := range args {
		if err = InspectItem(name, cwhub.PARSERS, noMetrics); err != nil {
			return err
		}
	}

	return nil
}

func NewParsersInspectCmd() *cobra.Command {
	cmdParsersInspect := &cobra.Command{
		Use:               "inspect <parser>",
		Short:             "Inspect a parser",
		Long:              `Inspect a parser`,
		Example:           `cscli parsers inspect crowdsecurity/httpd-logs crowdsecurity/sshd-logs`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS, args, toComplete)
		},
		RunE: runParsersInspect,
	}

	flags := cmdParsersInspect.Flags()
	flags.StringP("url", "u", "", "Prometheus url")
	flags.Bool("no-metrics", false, "Don't show metrics (when cscli.output=human)")

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
		Use:   "list [parser... | -a]",
		Short: "List parsers",
		Long:  `List of installed/available/specified parsers`,
		Example: `cscli parsers list
cscli parsers list -a
cscli parsers list crowdsecurity/caddy-logs crowdsecurity/sshd-logs`,
		DisableAutoGenTag: true,
		RunE:              runParsersList,
	}

	flags := cmdParsersList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdParsersList
}
