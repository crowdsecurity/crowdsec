package main

import (
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
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

	cmdParsers.AddCommand(NewParsersInstallCmd())
	cmdParsers.AddCommand(NewParsersRemoveCmd())
	cmdParsers.AddCommand(NewParsersUpgradeCmd())
	cmdParsers.AddCommand(NewParsersInspectCmd())
	cmdParsers.AddCommand(NewParsersListCmd())

	return cmdParsers
}

func NewParsersInstallCmd() *cobra.Command {
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
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, name := range args {
				t := cwhub.GetItem(cwhub.PARSERS, name)
				if t == nil {
					nearestItem, score := GetDistance(cwhub.PARSERS, name)
					Suggest(cwhub.PARSERS, name, nearestItem.Name, score, ignoreError)
					continue
				}
				if err := cwhub.InstallItem(csConfig, name, cwhub.PARSERS, forceAction, downloadOnly); err != nil {
					if !ignoreError {
						return fmt.Errorf("error while installing '%s': %w", name, err)
					}
					log.Errorf("Error while installing '%s': %s", name, err)
				}
			}
			return nil
		},
	}

	cmdParsersInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdParsersInstall.PersistentFlags().BoolVar(&forceAction, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdParsersInstall.PersistentFlags().BoolVar(&ignoreError, "ignore", false, "Ignore errors when installing multiple parsers")

	return cmdParsersInstall
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
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				cwhub.RemoveMany(csConfig, cwhub.PARSERS, "", all, purge, forceAction)
				return nil
			}

			if len(args) == 0 {
				return fmt.Errorf("specify at least one parser to remove or '--all'")
			}

			for _, name := range args {
				cwhub.RemoveMany(csConfig, cwhub.PARSERS, name, all, purge, forceAction)
			}

			return nil
		},
	}

	cmdParsersRemove.PersistentFlags().BoolVar(&purge, "purge", false, "Delete source file too")
	cmdParsersRemove.PersistentFlags().BoolVar(&forceAction, "force", false, "Force remove : Remove tainted and outdated files")
	cmdParsersRemove.PersistentFlags().BoolVar(&all, "all", false, "Delete all the parsers")

	return cmdParsersRemove
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
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				cwhub.UpgradeConfig(csConfig, cwhub.PARSERS, "", forceAction)
			} else {
				if len(args) == 0 {
					return fmt.Errorf("specify at least one parser to upgrade or '--all'")
				}
				for _, name := range args {
					cwhub.UpgradeConfig(csConfig, cwhub.PARSERS, name, forceAction)
				}
			}
			return nil
		},
	}

	cmdParsersUpgrade.PersistentFlags().BoolVar(&all, "all", false, "Upgrade all the parsers")
	cmdParsersUpgrade.PersistentFlags().BoolVar(&forceAction, "force", false, "Force upgrade : Overwrite tainted and outdated files")

	return cmdParsersUpgrade
}

func NewParsersInspectCmd() *cobra.Command {
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

	return cmdParsersInspect
}

func NewParsersListCmd() *cobra.Command {
	var cmdParsersList = &cobra.Command{
		Use:   "list [name]",
		Short: "List all parsers or given one",
		Long:  `List all parsers or given one`,
		Example: `cscli parsers list
cscli parser list crowdsecurity/xxx`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			ListItems(color.Output, []string{cwhub.PARSERS}, args, false, true, all)
		},
	}

	cmdParsersList.PersistentFlags().BoolVarP(&all, "all", "a", false, "List disabled items as well")

	return cmdParsersList
}
