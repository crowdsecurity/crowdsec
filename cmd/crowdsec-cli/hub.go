package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewHubCmd() *cobra.Command {
	/* ---- HUB COMMAND */
	var cmdHub = &cobra.Command{
		Use:   "hub [action]",
		Short: "Manage Hub",
		Long: `
Hub management

List/update parsers/scenarios/postoverflows/collections from [Crowdsec Hub](https://hub.crowdsec.net).
Hub is manage by cscli, to get latest hub files from [Crowdsec Hub](https://hub.crowdsec.net), you need to update.
		`,
		Example: `
cscli hub list   # List all installed configurations
cscli hub update # Download list of available configurations from the hub
		`,
		Args: cobra.ExactArgs(0),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if csConfig.Cscli == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			return nil
		},
	}
	cmdHub.PersistentFlags().StringVarP(&cwhub.HubBranch, "branch", "b", "", "Use given branch from hub")

	var cmdHubList = &cobra.Command{
		Use:   "list",
		Short: "List installed configs",
		Long:  ``,
		Args:  cobra.ExactArgs(0),
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
	cmdHub.PersistentFlags().BoolVarP(&listAll, "all", "a", false, "List as well disabled items")
	cmdHub.AddCommand(cmdHubList)

	var cmdHubUpdate = &cobra.Command{
		Use:   "update",
		Short: "Fetch available configs from hub",
		Long: `
Fetches the [.index.json](https://github.com/crowdsecurity/hub/blob/master/.index.json) file from hub, containing the list of available configs.
`,
		Args: cobra.ExactArgs(0),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if csConfig.Cscli == nil {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			if err := setHubBranch(); err != nil {
				return fmt.Errorf("error while setting hub branch: %s", err)
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.UpdateHubIdx(csConfig.Cscli); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
		},
	}
	cmdHub.AddCommand(cmdHubUpdate)

	return cmdHub
}
