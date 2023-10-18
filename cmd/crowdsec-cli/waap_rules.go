package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func NewWafRulesCmd() *cobra.Command {
	var cmdWafRules = &cobra.Command{
		Use:   "waf-rules [action] [config]",
		Short: "Install/Remove/Upgrade/Inspect waf-rule(s) from hub",
		Example: `cscli waf-rules install crowdsecurity/core-rule-set
cscli waf-rules inspect crowdsecurity/core-rule-set
cscli waf-rules upgrade crowdsecurity/core-rule-set
cscli waf-rules list
cscli waf-rules remove crowdsecurity/core-rule-set
`,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{"waf-rule"},
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadHub(); err != nil {
				log.Fatal(err)
			}
			if csConfig.Hub == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			if err := cwhub.SetHubBranch(); err != nil {
				return fmt.Errorf("error while setting hub branch: %s", err)
			}

			if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Info("Run 'sudo cscli hub update' to get the hub index")
				log.Fatalf("Failed to get Hub index : %v", err)
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

	cmdWafRules.AddCommand(NewWafRulesInstallCmd())
	cmdWafRules.AddCommand(NewWafRulesRemoveCmd())
	cmdWafRules.AddCommand(NewWafRulesUpgradeCmd())
	cmdWafRules.AddCommand(NewWafRulesInspectCmd())
	cmdWafRules.AddCommand(NewWafRulesListCmd())

	return cmdWafRules
}

func NewWafRulesInstallCmd() *cobra.Command {
	var ignoreError bool

	var cmdWafRulesInstall = &cobra.Command{
		Use:               "install [config]",
		Short:             "Install given waap-rule(s)",
		Long:              `Fetch and install given waap-rule(s) from hub`,
		Example:           `cscli waap-rules install crowdsec/xxx crowdsec/xyz`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.WAAP_RULES, args, toComplete)
		},
		Run: func(cmd *cobra.Command, args []string) {
			for _, name := range args {
				t := cwhub.GetItem(cwhub.WAAP_RULES, name)
				if t == nil {
					nearestItem, score := GetDistance(cwhub.WAAP_RULES, name)
					Suggest(cwhub.WAAP_RULES, name, nearestItem.Name, score, ignoreError)
					continue
				}
				if err := cwhub.InstallItem(csConfig, name, cwhub.WAAP_RULES, forceAction, downloadOnly); err != nil {
					if ignoreError {
						log.Errorf("Error while installing '%s': %s", name, err)
					} else {
						log.Fatalf("Error while installing '%s': %s", name, err)
					}
				}
			}
		},
	}
	cmdWafRulesInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdWafRulesInstall.PersistentFlags().BoolVar(&forceAction, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdWafRulesInstall.PersistentFlags().BoolVar(&ignoreError, "ignore", false, "Ignore errors when installing multiple waf rules")

	return cmdWafRulesInstall
}

func NewWafRulesRemoveCmd() *cobra.Command {
	var cmdWafRulesRemove = &cobra.Command{
		Use:               "remove [config]",
		Short:             "Remove given waf-rule(s)",
		Long:              `Remove given waf-rule(s) from hub`,
		Aliases:           []string{"delete"},
		Example:           `cscli waf-rules remove crowdsec/xxx crowdsec/xyz`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.WAAP_RULES, args, toComplete)
		},
		Run: func(cmd *cobra.Command, args []string) {
			if all {
				cwhub.RemoveMany(csConfig, cwhub.WAAP_RULES, "", all, purge, forceAction)
				return
			}

			if len(args) == 0 {
				log.Fatalf("Specify at least one waf rule to remove or '--all' flag.")
			}

			for _, name := range args {
				cwhub.RemoveMany(csConfig, cwhub.WAAP_RULES, name, all, purge, forceAction)
			}
		},
	}
	cmdWafRulesRemove.PersistentFlags().BoolVar(&purge, "purge", false, "Delete source file too")
	cmdWafRulesRemove.PersistentFlags().BoolVar(&forceAction, "force", false, "Force remove : Remove tainted and outdated files")
	cmdWafRulesRemove.PersistentFlags().BoolVar(&all, "all", false, "Delete all the waf rules")

	return cmdWafRulesRemove
}

func NewWafRulesUpgradeCmd() *cobra.Command {
	var cmdWafRulesUpgrade = &cobra.Command{
		Use:               "upgrade [config]",
		Short:             "Upgrade given waf-rule(s)",
		Long:              `Fetch and upgrade given waf-rule(s) from hub`,
		Example:           `cscli waf-rules upgrade crowdsec/xxx crowdsec/xyz`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.WAAP_RULES, args, toComplete)
		},
		Run: func(cmd *cobra.Command, args []string) {
			if all {
				cwhub.UpgradeConfig(csConfig, cwhub.WAAP_RULES, "", forceAction)
			} else {
				if len(args) == 0 {
					log.Fatalf("no target waf rule to upgrade")
				}
				for _, name := range args {
					cwhub.UpgradeConfig(csConfig, cwhub.WAAP_RULES, name, forceAction)
				}
			}
		},
	}
	cmdWafRulesUpgrade.PersistentFlags().BoolVar(&all, "all", false, "Upgrade all the waf rules")
	cmdWafRulesUpgrade.PersistentFlags().BoolVar(&forceAction, "force", false, "Force upgrade : Overwrite tainted and outdated files")

	return cmdWafRulesUpgrade
}

func NewWafRulesInspectCmd() *cobra.Command {
	var cmdWafRulesInspect = &cobra.Command{
		Use:               "inspect [name]",
		Short:             "Inspect given waf rule",
		Long:              `Inspect given waf rule`,
		Example:           `cscli waf-rules inspect crowdsec/xxx`,
		DisableAutoGenTag: true,
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.WAAP_RULES, args, toComplete)
		},
		Run: func(cmd *cobra.Command, args []string) {
			InspectItem(args[0], cwhub.WAAP_RULES)
		},
	}
	cmdWafRulesInspect.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "", "Prometheus url")

	return cmdWafRulesInspect
}

func NewWafRulesListCmd() *cobra.Command {
	var cmdWafRulesList = &cobra.Command{
		Use:   "list [name]",
		Short: "List all waf rules or given one",
		Long:  `List all waf rules or given one`,
		Example: `cscli waf-rules list
cscli waf-rules list crowdsecurity/xxx`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			ListItems(color.Output, []string{cwhub.WAAP_RULES}, args, false, true, all)
		},
	}
	cmdWafRulesList.PersistentFlags().BoolVarP(&all, "all", "a", false, "List disabled items as well")

	return cmdWafRulesList
}
