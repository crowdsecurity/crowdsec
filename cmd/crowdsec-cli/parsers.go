package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

func NewParsersCmd() *cobra.Command {
	var cmdParsers = &cobra.Command{
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

	var ignoreError bool
	var cmdParsersInstall = &cobra.Command{
		Use:               "install [config]",
		Short:             "Install given parser(s)",
		Long:              `Fetch and install given parser(s) from hub`,
		Example:           `cscli parsers install crowdsec/xxx crowdsec/xyz`,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compAllItems(cwhub.PARSERS, args, toComplete)
		},
		Run: func(cmd *cobra.Command, args []string) {
			for _, name := range args {
				t := cwhub.GetItem(cwhub.PARSERS, name)
				if t == nil {
					nearestItem, score := GetDistance(cwhub.PARSERS, name)
					errMsg := ""
					if score < MaxDistance {
						errMsg = fmt.Sprintf("unable to find parser '%s', did you mean %s ?", name, nearestItem.Name)
					} else {
						errMsg = fmt.Sprintf("unable to find parser '%s'", name)
					}
					if ignoreError {
						log.Error(errMsg)
					} else {
						log.Fatalf(errMsg)
					}
				}
				if err := cwhub.InstallItem(csConfig, name, cwhub.PARSERS, forceAction, downloadOnly); err != nil {
					if ignoreError {
						log.Errorf("Error while installing '%s': %s", name, err)
					} else {
						log.Fatalf("Error while installing '%s': %s", name, err)
					}
				}
			}
		},
	}
	cmdParsersInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdParsersInstall.PersistentFlags().BoolVar(&forceAction, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdParsersInstall.PersistentFlags().BoolVar(&ignoreError, "ignore", false, "Ignore errors when installing multiple parsers")
	cmdParsers.AddCommand(cmdParsersInstall)

	var cmdParsersRemove = &cobra.Command{
		Use:               "remove [config]",
		Short:             "Remove given parser(s)",
		Long:              `Remove given parse(s) from hub`,
		Aliases:           []string{"delete"},
		Example:           `cscli parsers remove crowdsec/xxx crowdsec/xyz`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS, args, toComplete)
		},
		Run: func(cmd *cobra.Command, args []string) {
			if all {
				cwhub.RemoveMany(csConfig, cwhub.PARSERS, "", all, purge, forceAction)
				return
			}

			if len(args) == 0 {
				log.Fatalf("Specify at least one parser to remove or '--all' flag.")
			}

			for _, name := range args {
				cwhub.RemoveMany(csConfig, cwhub.PARSERS, name, all, purge, forceAction)
			}
		},
	}
	cmdParsersRemove.PersistentFlags().BoolVar(&purge, "purge", false, "Delete source file too")
	cmdParsersRemove.PersistentFlags().BoolVar(&forceAction, "force", false, "Force remove : Remove tainted and outdated files")
	cmdParsersRemove.PersistentFlags().BoolVar(&all, "all", false, "Delete all the parsers")
	cmdParsers.AddCommand(cmdParsersRemove)

	var cmdParsersUpgrade = &cobra.Command{
		Use:               "upgrade [config]",
		Short:             "Upgrade given parser(s)",
		Long:              `Fetch and upgrade given parser(s) from hub`,
		Example:           `cscli parsers upgrade crowdsec/xxx crowdsec/xyz`,
		DisableAutoGenTag: true,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS, args, toComplete)
		},
		Run: func(cmd *cobra.Command, args []string) {
			if all {
				cwhub.UpgradeConfig(csConfig, cwhub.PARSERS, "", forceAction)
			} else {
				if len(args) == 0 {
					log.Fatalf("no target parser to upgrade")
				}
				for _, name := range args {
					cwhub.UpgradeConfig(csConfig, cwhub.PARSERS, name, forceAction)
				}
			}
		},
	}
	cmdParsersUpgrade.PersistentFlags().BoolVar(&all, "all", false, "Upgrade all the parsers")
	cmdParsersUpgrade.PersistentFlags().BoolVar(&forceAction, "force", false, "Force upgrade : Overwrite tainted and outdated files")
	cmdParsers.AddCommand(cmdParsersUpgrade)

	var cmdParsersInspect = &cobra.Command{
		Use:               "inspect [name]",
		Short:             "Inspect given parser",
		Long:              `Inspect given parser`,
		Example:           `cscli parsers inspect crowdsec/xxx`,
		DisableAutoGenTag: true,
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cwhub.PARSERS, args, toComplete)
		},
		Run: func(cmd *cobra.Command, args []string) {
			InspectItem(args[0], cwhub.PARSERS)
		},
	}
	cmdParsersInspect.PersistentFlags().StringVarP(&prometheusURL, "url", "u", "", "Prometheus url")
	cmdParsers.AddCommand(cmdParsersInspect)

	var cmdParsersList = &cobra.Command{
		Use:   "list [name]",
		Short: "List all parsers or given one",
		Long:  `List all parsers or given one`,
		Example: `cscli parsers list
cscli parser list crowdsecurity/xxx`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			ListItems([]string{cwhub.PARSERS}, args, false, true, all)
		},
	}
	cmdParsersList.PersistentFlags().BoolVarP(&all, "all", "a", false, "List disabled items as well")
	cmdParsers.AddCommand(cmdParsersList)

	return cmdParsers
}
