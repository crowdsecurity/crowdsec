package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewWaapRulesCmd() *cobra.Command {
	cmdWaapRules := &cobra.Command{
		Use:   "waap-rules <action> [waap-rule]...",
		Short: "Manage hub waap rules",
		Example: `cscli waap-rules list -a
cscli waap-rules install crowdsecurity/crs
cscli waap-rules inspect crowdsecurity/crs
cscli waap-rules upgrade crowdsecurity/crs
cscli waap-rules remove crowdsecurity/crs
`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"waap-rule"},
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if _, err := require.Hub(csConfig); err != nil {
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

	cmdWaapRules.AddCommand(NewCmdWaapRulesInstall())
	cmdWaapRules.AddCommand(NewCmdWaapRulesRemove())
	cmdWaapRules.AddCommand(NewCmdWaapRulesUpgrade())
	cmdWaapRules.AddCommand(NewCmdWaapRulesInspect())
	cmdWaapRules.AddCommand(NewCmdWaapRulesList())

	return cmdWaapRules
}

func runWaapRulesInstall(cmd *cobra.Command, args []string) error {
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

	hub, err := cwhub.GetHub()
	if err != nil {
		return err
	}

	for _, name := range args {
		t := hub.GetItem(cwhub.WAAP_RULES, name)
		if t == nil {
			nearestItem, score := GetDistance(cwhub.WAAP_RULES, name)
			Suggest(cwhub.WAAP_RULES, name, nearestItem.Name, score, ignoreError)

			continue
		}

		if err := hub.InstallItem(name, cwhub.WAAP_RULES, force, downloadOnly); err != nil {
			if !ignoreError {
				return fmt.Errorf("error while installing '%s': %w", name, err)
			}
			log.Errorf("Error while installing '%s': %s", name, err)
		}
	}

	return nil
}

func NewCmdWaapRulesInstall() *cobra.Command {
	cmdWaapRulesInstall := &cobra.Command{
		Use:               "install <waap-rule>...",
		Short:             "Install given waap rule(s)",
		Long:              `Fetch and install one or more waap rules from the hub`,
		Example:           `cscli waap-rules install crowdsecurity/crs`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.WAAP_RULES, args, toComplete)
		},
		RunE: runWaapRulesInstall,
	}

	flags := cmdWaapRulesInstall.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install: overwrite tainted and outdated files")
	flags.Bool("ignore", false, "Ignore errors when installing multiple waap rules")

	return cmdWaapRulesInstall
}

func runWaapRulesRemove(cmd *cobra.Command, args []string) error {
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

	hub, err := cwhub.GetHub()
	if err != nil {
		return err
	}

	if all {
		err := hub.RemoveMany(cwhub.WAAP_RULES, "", all, purge, force)
		if err != nil {
			return err
		}

		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one waap rule to remove or '--all'")
	}

	for _, name := range args {
		err := hub.RemoveMany(cwhub.WAAP_RULES, name, all, purge, force)
		if err != nil {
			return err
		}
	}

	return nil
}

func NewCmdWaapRulesRemove() *cobra.Command {
	cmdWaapRulesRemove := &cobra.Command{
		Use:               "remove <waap-rule>...",
		Short:             "Remove given waap rule(s)",
		Long:              `remove one or more waap rules`,
		Example:           `cscli waap-rules remove crowdsecurity/crs`,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.WAAP_RULES, args, toComplete)
		},
		RunE: runWaapRulesRemove,
	}

	flags := cmdWaapRulesRemove.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove: remove tainted and outdated files")
	flags.Bool("all", false, "Remove all the waap rules")

	return cmdWaapRulesRemove
}

func runWaapRulesUpgrade(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	force, err := flags.GetBool("force")
	if err != nil {
		return err
	}

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	hub, err := cwhub.GetHub()
	if err != nil {
		return err
	}

	if all {
		if err := hub.UpgradeConfig(cwhub.WAAP_RULES, "", force); err != nil {
			return err
		}
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one waap rule to upgrade or '--all'")
	}

	for _, name := range args {
		if err := hub.UpgradeConfig(cwhub.WAAP_RULES, name, force); err != nil {
			return err
		}
	}

	return nil
}

func NewCmdWaapRulesUpgrade() *cobra.Command {
	cmdWaapRulesUpgrade := &cobra.Command{
		Use:               "upgrade <waap-rule>...",
		Short:             "Upgrade given waap rule(s)",
		Long:              `Fetch and upgrade one or more waap rules from the hub`,
		Example:           `cscli waap-rules upgrade crowdsecurity/crs`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.WAAP_RULES, args, toComplete)
		},
		RunE: runWaapRulesUpgrade,
	}

	flags := cmdWaapRulesUpgrade.Flags()
	flags.BoolP("all", "a", false, "Upgrade all the waap rules")
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmdWaapRulesUpgrade
}

func runWaapRulesInspect(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	url, err := flags.GetString("url")
	if err != nil {
		return err
	}

	if url != "" {
		csConfig.Cscli.PrometheusUrl = url
	}

	noMetrics, err := flags.GetBool("no-metrics")
	if err != nil {
		return err
	}

	for _, name := range args {
		if err = InspectItem(name, cwhub.WAAP_RULES, noMetrics); err != nil {
			return err
		}
	}

	return nil
}

func NewCmdWaapRulesInspect() *cobra.Command {
	cmdWaapRulesInspect := &cobra.Command{
		Use:               "inspect <waap-rule>",
		Short:             "Inspect a waap rule",
		Long:              `Inspect a waap rule`,
		Example:           `cscli waap-rules inspect crowdsecurity/crs`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.WAAP_RULES, args, toComplete)
		},
		RunE: runWaapRulesInspect,
	}

	flags := cmdWaapRulesInspect.Flags()
	flags.StringP("url", "u", "", "Prometheus url")
	flags.Bool("no-metrics", false, "Don't show metrics (when cscli.output=human)")

	return cmdWaapRulesInspect
}

func runWaapRulesList(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	if err = ListItems(color.Output, []string{cwhub.WAAP_RULES}, args, false, true, all); err != nil {
		return err
	}

	return nil
}

func NewCmdWaapRulesList() *cobra.Command {
	cmdWaapRulesList := &cobra.Command{
		Use:   "list [waap-rule]...",
		Short: "List waap rules",
		Long:  `List of installed/available/specified waap rules`,
		Example: `cscli waap-rules list
cscli waap-rules list -a
cscli waap-rules list crowdsecurity/crs`,
		DisableAutoGenTag: true,
		RunE:              runWaapRulesList,
	}

	flags := cmdWaapRulesList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdWaapRulesList
}
