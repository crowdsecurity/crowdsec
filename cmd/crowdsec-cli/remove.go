package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var purge_remove, remove_all bool

func RemoveMany(ttype string, name string) {
	var err error
	var disabled int
	for _, v := range cwhub.HubIdx[ttype] {
		if name != "" && v.Name == name {
			v, err = cwhub.DisableItem(v, cwhub.Installdir, cwhub.Hubdir, purge_remove)
			if err != nil {
				log.Fatalf("unable to disable %s : %v", v.Name, err)
			}
			disabled += 1
			cwhub.HubIdx[ttype][v.Name] = v
			return
		} else if name == "" && remove_all {
			v, err = cwhub.DisableItem(v, cwhub.Installdir, cwhub.Hubdir, purge_remove)
			if err != nil {
				log.Fatalf("unable to disable %s : %v", v.Name, err)
			}
			cwhub.HubIdx[ttype][v.Name] = v
			disabled += 1
		}
	}
	if name != "" && !remove_all {
		log.Errorf("%s not found", name)
		return
	}
	log.Infof("Disabled %d items", disabled)
}

func NewRemoveCmd() *cobra.Command {

	var cmdRemove = &cobra.Command{
		Use:   "remove [type] <config>",
		Short: "Remove/disable configuration(s)",
		Long: `
 Remove local configuration. 
 
[type] must be parser, scenario, postoverflow, collection

[config_name] must be a valid config name from [Crowdsec Hub](https://hub.crowdsec.net) or locally installed.
 `,
		Example: `cscli remove [type] [config_name]`,
		Args:    cobra.MinimumNArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !config.configured {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}
			return nil
		},
	}
	cmdRemove.PersistentFlags().BoolVar(&purge_remove, "purge", false, "Delete source file in ~/.cscli/hub/ too")
	cmdRemove.PersistentFlags().BoolVar(&remove_all, "all", false, "Delete all the files in selected scope")
	var cmdRemoveParser = &cobra.Command{
		Use:   "parser <config>",
		Short: "Remove/disable parser",
		Long:  `<config> must be a valid parser.`,
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}

			if remove_all && len(args) == 0 {
				RemoveMany(cwhub.PARSERS, "")
			} else if len(args) == 1 {
				RemoveMany(cwhub.PARSERS, args[0])
			} else {
				_ = cmd.Help()
				return
			}
			//fmt.Println("remove/disable parser: " + strings.Join(args, " "))
		},
	}
	cmdRemove.AddCommand(cmdRemoveParser)
	var cmdRemoveScenario = &cobra.Command{
		Use:   "scenario [config]",
		Short: "Remove/disable scenario",
		Long:  `<config> must be a valid scenario.`,
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if remove_all && len(args) == 0 {
				RemoveMany(cwhub.SCENARIOS, "")
			} else if len(args) == 1 {
				RemoveMany(cwhub.SCENARIOS, args[0])
			} else {
				_ = cmd.Help()
				return
			}
		},
	}
	cmdRemove.AddCommand(cmdRemoveScenario)
	var cmdRemoveCollection = &cobra.Command{
		Use:   "collection [config]",
		Short: "Remove/disable collection",
		Long:  `<config> must be a valid collection.`,
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if remove_all && len(args) == 0 {
				RemoveMany(cwhub.COLLECTIONS, "")
			} else if len(args) == 1 {
				RemoveMany(cwhub.COLLECTIONS, args[0])
			} else {
				_ = cmd.Help()
				return
			}
		},
	}
	cmdRemove.AddCommand(cmdRemoveCollection)

	var cmdRemovePostoverflow = &cobra.Command{
		Use:   "postoverflow [config]",
		Short: "Remove/disable postoverflow parser",
		Long:  `<config> must be a valid collection.`,
		Args:  cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if remove_all && len(args) == 0 {
				RemoveMany(cwhub.PARSERS_OVFLW, "")
			} else if len(args) == 1 {
				RemoveMany(cwhub.PARSERS_OVFLW, args[0])
			} else {
				_ = cmd.Help()
				return
			}
		},
	}
	cmdRemove.AddCommand(cmdRemovePostoverflow)

	return cmdRemove
}
