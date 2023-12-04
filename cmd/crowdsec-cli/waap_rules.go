package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/waf"
	"github.com/crowdsecurity/crowdsec/pkg/waf/waap_rule"
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
			if _, err := require.Hub(csConfig, require.RemoteHub(csConfig)); err != nil {
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
		RunE: itemsInstallRunner(hubItemTypes[cwhub.WAAP_RULES]),
	}

	flags := cmdWaapRulesInstall.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install: overwrite tainted and outdated files")
	flags.Bool("ignore", false, "Ignore errors when installing multiple waap rules")

	return cmdWaapRulesInstall
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
		RunE: itemsRemoveRunner(hubItemTypes[cwhub.WAAP_RULES]),
	}

	flags := cmdWaapRulesRemove.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove: remove tainted and outdated files")
	flags.Bool("all", false, "Remove all the waap rules")

	return cmdWaapRulesRemove
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
		RunE: itemsUpgradeRunner(hubItemTypes[cwhub.WAAP_RULES]),
	}

	flags := cmdWaapRulesUpgrade.Flags()
	flags.BoolP("all", "a", false, "Upgrade all the waap rules")
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmdWaapRulesUpgrade
}

func WaapRulesInspectRunner(itemType hubItemType) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		f := itemsInspectRunner(hubItemTypes[cwhub.WAAP_RULES])
		if err := f(cmd, args); err != nil {
			return err
		}
		if csConfig.Cscli.Output == "human" {
			hub, _ := require.Hub(csConfig, nil)
			for _, name := range args {
				hubItem := hub.GetItem(itemType.name, name)
				waapRule := waf.AppsecCollectionConfig{}
				yamlContent, err := os.ReadFile(hubItem.State.LocalPath)
				if err != nil {
					return fmt.Errorf("unable to read file %s : %s", hubItem.State.LocalPath, err)
				}
				if err := yaml.Unmarshal(yamlContent, &waapRule); err != nil {
					return fmt.Errorf("unable to unmarshal yaml file %s : %s", hubItem.State.LocalPath, err)
				}

				for _, ruleType := range waap_rule.SupportedTypes() {
					fmt.Printf("\n%s format:\n", cases.Title(language.Und, cases.NoLower).String(ruleType))
					for _, rule := range waapRule.Rules {
						convertedRule, _, err := rule.Convert(ruleType, waapRule.Name)
						if err != nil {
							return fmt.Errorf("unable to convert rule %s : %s", rule.Name, err)
						}
						fmt.Println(convertedRule)
					}
				}
			}
		}
		return nil
	}
}

func NewCmdWaapRulesInspect() *cobra.Command {
	//FIXME; show the "compiled" rule
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
		RunE: WaapRulesInspectRunner(hubItemTypes[cwhub.WAAP_RULES]),
	}

	flags := cmdWaapRulesInspect.Flags()
	flags.StringP("url", "u", "", "Prometheus url")
	flags.Bool("no-metrics", false, "Don't show metrics (when cscli.output=human)")

	return cmdWaapRulesInspect
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
		RunE:              itemsListRunner(hubItemTypes[cwhub.WAAP_RULES]),
	}

	flags := cmdWaapRulesList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdWaapRulesList
}
