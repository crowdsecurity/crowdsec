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
		Args: cobra.MinimumNArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if csConfig.Cscli == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			if err := setHubBranch(); err != nil {
				return fmt.Errorf("error while setting hub branch: %s", err)
			}
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if cmd.Name() == "inspect" || cmd.Name() == "list" {
				return
			}
			log.Infof("Run 'sudo systemctl reload crowdsec' for the new configuration to be effective.")
		},
	}

	var cmdParsersInstall = &cobra.Command{
		Use:     "install [config]",
		Short:   "Install given parser(s)",
		Long:    `Fetch and install given parser(s) from hub`,
		Example: `cscli parsers install crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}
			for _, name := range args {
				InstallItem(name, cwhub.PARSERS, forceAction)
			}
		},
	}
	cmdParsersInstall.PersistentFlags().BoolVarP(&downloadOnly, "download-only", "d", false, "Only download packages, don't enable")
	cmdParsersInstall.PersistentFlags().BoolVar(&forceAction, "force", false, "Force install : Overwrite tainted and outdated files")
	cmdParsers.AddCommand(cmdParsersInstall)

	var cmdParsersRemove = &cobra.Command{
		Use:     "remove [config]",
		Short:   "Remove given parser(s)",
		Long:    `Remove given parse(s) from hub`,
		Example: `cscli parsers remove crowdsec/xxx crowdsec/xyz`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}

			if all {
				RemoveMany(cwhub.PARSERS, "")
			} else {
				for _, name := range args {
					RemoveMany(cwhub.PARSERS, name)
				}
			}
		},
	}
	cmdParsersRemove.PersistentFlags().BoolVar(&purge, "purge", false, "Delete source file too")
	cmdParsersRemove.PersistentFlags().BoolVar(&forceAction, "force", false, "Force remove : Remove tainted and outdated files")
	cmdParsersRemove.PersistentFlags().BoolVar(&all, "all", false, "Delete all the parsers")
	cmdParsers.AddCommand(cmdParsersRemove)

	var cmdParsersUpgrade = &cobra.Command{
		Use:     "upgrade [config]",
		Short:   "Upgrade given parser(s)",
		Long:    `Fetch and upgrade given parser(s) from hub`,
		Example: `cscli parsers upgrade crowdsec/xxx crowdsec/xyz`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}
			if all {
				UpgradeConfig(cwhub.PARSERS, "", forceAction)
			} else {
				for _, name := range args {
					UpgradeConfig(cwhub.PARSERS, name, forceAction)
				}
			}
		},
	}
	cmdParsersUpgrade.PersistentFlags().BoolVar(&all, "all", false, "Upgrade all the parsers")
	cmdParsersUpgrade.PersistentFlags().BoolVar(&forceAction, "force", false, "Force upgrade : Overwrite tainted and outdated files")
	cmdParsers.AddCommand(cmdParsersUpgrade)

	var cmdParsersInspect = &cobra.Command{
		Use:     "inspect [name]",
		Short:   "Inspect given parser",
		Long:    `Inspect given parser`,
		Example: `cscli parsers inspect crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}

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
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}
			ListItem(cwhub.PARSERS, args)
		},
	}
	cmdParsersList.PersistentFlags().BoolVarP(&all, "all", "a", false, "List as well disabled items")
	cmdParsers.AddCommand(cmdParsersList)

	return cmdParsers
}
