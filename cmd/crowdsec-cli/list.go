package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	"github.com/enescakir/emoji"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var listAll bool

func doListing(ttype string, args []string) {

	var pkgst []map[string]string

	if len(args) == 1 {
		pkgst = cwhub.HubStatus(ttype, args[0], listAll)
	} else {
		pkgst = cwhub.HubStatus(ttype, "", listAll)
	}

	if config.output == "human" {

		table := tablewriter.NewWriter(os.Stdout)
		table.SetCenterSeparator("")
		table.SetColumnSeparator("")

		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetHeader([]string{"Name", fmt.Sprintf("%v Status", emoji.Package), "Version", "Local Path"})
		for _, v := range pkgst {
			table.Append([]string{v["name"], v["utf8_status"], v["local_version"], v["local_path"]})
		}
		table.Render()
	} else if config.output == "json" {
		x, err := json.MarshalIndent(pkgst, "", " ")
		if err != nil {
			log.Fatalf("failed to unmarshal")
		}
		fmt.Printf("%s", string(x))
	} else if config.output == "raw" {
		for _, v := range pkgst {
			fmt.Printf("%s %s\n", v["name"], v["description"])
		}
	}
}

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
			if !config.configured {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}

			cwhub.DisplaySummary()
			log.Printf("PARSERS:")
			doListing(cwhub.PARSERS, args)
			log.Printf("SCENARIOS:")
			doListing(cwhub.SCENARIOS, args)
			log.Printf("COLLECTIONS:")
			doListing(cwhub.COLLECTIONS, args)
			log.Printf("POSTOVERFLOWS:")
			doListing(cwhub.PARSERS_OVFLW, args)
		},
	}
	cmdList.PersistentFlags().BoolVarP(&listAll, "all", "a", false, "List as well disabled items")

	var cmdListParsers = &cobra.Command{
		Use:   "parsers [-a]",
		Short: "List enabled parsers",
		Long:  ``,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			doListing(cwhub.PARSERS, args)
		},
	}
	cmdList.AddCommand(cmdListParsers)

	var cmdListScenarios = &cobra.Command{
		Use:   "scenarios [-a]",
		Short: "List enabled scenarios",
		Long:  ``,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			doListing(cwhub.SCENARIOS, args)
		},
	}
	cmdList.AddCommand(cmdListScenarios)

	var cmdListCollections = &cobra.Command{
		Use:   "collections [-a]",
		Short: "List enabled collections",
		Long:  ``,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			doListing(cwhub.COLLECTIONS, args)
		},
	}
	cmdList.AddCommand(cmdListCollections)

	var cmdListPostoverflows = &cobra.Command{
		Use:   "postoverflows [-a]",
		Short: "List enabled postoverflow parsers",
		Long:  ``,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			doListing(cwhub.PARSERS_OVFLW, args)
		},
	}
	cmdList.AddCommand(cmdListPostoverflows)

	return cmdList
}
