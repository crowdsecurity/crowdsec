package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var listAll bool

func NewListCmd() *cobra.Command {
	/* ---- LIST COMMAND */
	var cmdList = &cobra.Command{
		Use:   "list [-a]",
		Short: "List enabled configs",
		Long: `
List enabled configurations (parser/scenarios/collections) on your host.

It is possible to list also configuration from [Crowdsec Hub](https://hub.crowdsec.net) with the '-a' options.

[type] must be parsers, scenarios, postoverflows, collections
		`,
		Example: `cscli list  # List all local configurations
cscli list [type] # List all local configuration of type [type]
cscli list -a # List all local and remote configurations
		`,
		Args: cobra.ExactArgs(0),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if csConfig.Cscli == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}

			cwhub.DisplaySummary()
			log.Printf("PARSERS:")
			ListItem(cwhub.PARSERS, args)
			log.Printf("SCENARIOS:")
			ListItem(cwhub.SCENARIOS, args)
			log.Printf("COLLECTIONS:")
			ListItem(cwhub.COLLECTIONS, args)
			log.Printf("POSTOVERFLOWS:")
			ListItem(cwhub.PARSERS_OVFLW, args)
		},
	}
	cmdList.PersistentFlags().BoolVarP(&listAll, "all", "a", false, "List as well disabled items")

	var cmdListParsers = &cobra.Command{
		Use:   "parsers [-a]",
		Short: "List enabled parsers",
		Long:  ``,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			ListItem(cwhub.PARSERS, args)
		},
	}
	cmdList.AddCommand(cmdListParsers)

	var cmdListScenarios = &cobra.Command{
		Use:   "scenarios [-a]",
		Short: "List enabled scenarios",
		Long:  ``,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			ListItem(cwhub.SCENARIOS, args)
		},
	}
	cmdList.AddCommand(cmdListScenarios)

	var cmdListCollections = &cobra.Command{
		Use:   "collections [-a]",
		Short: "List enabled collections",
		Long:  ``,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			ListItem(cwhub.COLLECTIONS, args)
		},
	}
	cmdList.AddCommand(cmdListCollections)

	var cmdListPostoverflows = &cobra.Command{
		Use:   "postoverflows [-a]",
		Short: "List enabled postoverflow parsers",
		Long:  ``,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			ListItem(cwhub.PARSERS_OVFLW, args)
		},
	}
	cmdList.AddCommand(cmdListPostoverflows)

	return cmdList
}
