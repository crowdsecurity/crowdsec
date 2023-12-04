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

func NewAppsecRulesCmd() *cobra.Command {
	cmdAppsecRules := &cobra.Command{
		Use:   "appsec-rules <action> [appsec-rule]...",
		Short: "Manage hub appsec rules",
		Example: `cscli appsec-rules list -a
cscli appsec-rules install crowdsecurity/crs
cscli appsec-rules inspect crowdsecurity/crs
cscli appsec-rules upgrade crowdsecurity/crs
cscli appsec-rules remove crowdsecurity/crs
`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"appsec-rule"},
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

	cmdAppsecRules.AddCommand(NewCmdAppsecRulesInstall())
	cmdAppsecRules.AddCommand(NewCmdAppsecRulesRemove())
	cmdAppsecRules.AddCommand(NewCmdAppsecRulesUpgrade())
	cmdAppsecRules.AddCommand(NewCmdAppsecRulesInspect())
	cmdAppsecRules.AddCommand(NewCmdAppsecRulesList())

	return cmdAppsecRules
}

func NewCmdAppsecRulesInstall() *cobra.Command {
	cmdAppsecRulesInstall := &cobra.Command{
		Use:               "install <appsec-rule>...",
		Short:             "Install given appsec rule(s)",
		Long:              `Fetch and install one or more appsec rules from the hub`,
		Example:           `cscli appsec-rules install crowdsecurity/crs`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.APPSEC_RULES, args, toComplete)
		},
		RunE: itemsInstallRunner(hubItemTypes[cwhub.APPSEC_RULES]),
	}

	flags := cmdAppsecRulesInstall.Flags()
	flags.BoolP("download-only", "d", false, "Only download packages, don't enable")
	flags.Bool("force", false, "Force install: overwrite tainted and outdated files")
	flags.Bool("ignore", false, "Ignore errors when installing multiple appsec rules")

	return cmdAppsecRulesInstall
}

func NewCmdAppsecRulesRemove() *cobra.Command {
	cmdAppsecRulesRemove := &cobra.Command{
		Use:               "remove <appsec-rule>...",
		Short:             "Remove given appsec rule(s)",
		Long:              `remove one or more appsec rules`,
		Example:           `cscli appsec-rules remove crowdsecurity/crs`,
		Aliases:           []string{"delete"},
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.APPSEC_RULES, args, toComplete)
		},
		RunE: itemsRemoveRunner(hubItemTypes[cwhub.APPSEC_RULES]),
	}

	flags := cmdAppsecRulesRemove.Flags()
	flags.Bool("purge", false, "Delete source file too")
	flags.Bool("force", false, "Force remove: remove tainted and outdated files")
	flags.Bool("all", false, "Remove all the appsec rules")

	return cmdAppsecRulesRemove
}

func NewCmdAppsecRulesUpgrade() *cobra.Command {
	cmdAppsecRulesUpgrade := &cobra.Command{
		Use:               "upgrade <appsec-rule>...",
		Short:             "Upgrade given appsec rule(s)",
		Long:              `Fetch and upgrade one or more appsec rules from the hub`,
		Example:           `cscli appsec-rules upgrade crowdsecurity/crs`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.APPSEC_RULES, args, toComplete)
		},
		RunE: itemsUpgradeRunner(hubItemTypes[cwhub.APPSEC_RULES]),
	}

	flags := cmdAppsecRulesUpgrade.Flags()
	flags.BoolP("all", "a", false, "Upgrade all the appsec rules")
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmdAppsecRulesUpgrade
}

func AppsecRulesInspectRunner(itemType hubItemType) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		f := itemsInspectRunner(hubItemTypes[cwhub.APPSEC_RULES])
		if err := f(cmd, args); err != nil {
			return err
		}
		if csConfig.Cscli.Output == "human" {
			hub, _ := require.Hub(csConfig, nil)
			for _, name := range args {
				hubItem := hub.GetItem(itemType.name, name)
				appsecRule := waf.AppsecCollectionConfig{}
				yamlContent, err := os.ReadFile(hubItem.State.LocalPath)
				if err != nil {
					return fmt.Errorf("unable to read file %s : %s", hubItem.State.LocalPath, err)
				}
				if err := yaml.Unmarshal(yamlContent, &appsecRule); err != nil {
					return fmt.Errorf("unable to unmarshal yaml file %s : %s", hubItem.State.LocalPath, err)
				}

				for _, ruleType := range waap_rule.SupportedTypes() {
					fmt.Printf("\n%s format:\n", cases.Title(language.Und, cases.NoLower).String(ruleType))
					for _, rule := range appsecRule.Rules {
						convertedRule, _, err := rule.Convert(ruleType, appsecRule.Name)
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

func NewCmdAppsecRulesInspect() *cobra.Command {
	cmdAppsecRulesInspect := &cobra.Command{
		Use:               "inspect <appsec-rule>",
		Short:             "Inspect a appsec rule",
		Long:              `Inspect a appsec rule`,
		Example:           `cscli appsec-rules inspect crowdsecurity/crs`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.APPSEC_RULES, args, toComplete)
		},
		RunE: AppsecRulesInspectRunner(hubItemTypes[cwhub.APPSEC_RULES]),
	}

	flags := cmdAppsecRulesInspect.Flags()
	flags.StringP("url", "u", "", "Prometheus url")
	flags.Bool("no-metrics", false, "Don't show metrics (when cscli.output=human)")

	return cmdAppsecRulesInspect
}

func NewCmdAppsecRulesList() *cobra.Command {
	cmdAppsecRulesList := &cobra.Command{
		Use:   "list [appsec-rule]...",
		Short: "List appsec rules",
		Long:  `List of installed/available/specified appsec rules`,
		Example: `cscli appsec-rules list
cscli appsec-rules list -a
cscli appsec-rules list crowdsecurity/crs`,
		DisableAutoGenTag: true,
		RunE:              itemsListRunner(hubItemTypes[cwhub.APPSEC_RULES]),
	}

	flags := cmdAppsecRulesList.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmdAppsecRulesList
}
