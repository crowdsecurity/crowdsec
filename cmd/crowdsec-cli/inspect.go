package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"gopkg.in/yaml.v2"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

func InspectItem(name string, objectType string) {

	for _, hubItem := range cwhub.HubIdx[objectType] {
		if hubItem.Name != name {
			continue
		}
		buff, err := yaml.Marshal(hubItem)
		if err != nil {
			log.Fatalf("unable to marshal item : %s", err)
		}
		fmt.Printf("%s", string(buff))
	}
}

func NewInspectCmd() *cobra.Command {
	var cmdInspect = &cobra.Command{
		Use:   "inspect [type] [config]",
		Short: "Inspect configuration(s)",
		Long: `
Inspect give you full detail about local installed configuration.

[type] must be parser, scenario, postoverflow, collection.

[config_name] must be a valid config name from [Crowdsec Hub](https://hub.crowdsec.net) or locally installed.
`,
		Example: `cscli inspect parser crowdsec/xxx  
cscli inspect collection crowdsec/xxx`,
		Args: cobra.MinimumNArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !config.configured {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}
			return nil
		},
	}

	var cmdInspectParser = &cobra.Command{
		Use:     "parser [config]",
		Short:   "Inspect given log parser",
		Long:    `Inspect given parser from hub`,
		Example: `cscli inspect parser crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			InspectItem(args[0], cwhub.PARSERS)
		},
	}
	cmdInspect.AddCommand(cmdInspectParser)
	var cmdInspectScenario = &cobra.Command{
		Use:     "scenario [config]",
		Short:   "Inspect given scenario",
		Long:    `Inspect given scenario from hub`,
		Example: `cscli inspect scenario crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			InspectItem(args[0], cwhub.SCENARIOS)
		},
	}
	cmdInspect.AddCommand(cmdInspectScenario)

	var cmdInspectCollection = &cobra.Command{
		Use:     "collection [config]",
		Short:   "Inspect given collection",
		Long:    `Inspect given collection from hub`,
		Example: `cscli inspect collection crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			InspectItem(args[0], cwhub.COLLECTIONS)
		},
	}
	cmdInspect.AddCommand(cmdInspectCollection)

	var cmdInspectPostoverflow = &cobra.Command{
		Use:     "postoverflow [config]",
		Short:   "Inspect given postoverflow parser",
		Long:    `Inspect given postoverflow from hub.`,
		Example: `cscli inspect postoverflow crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			InspectItem(args[0], cwhub.PARSERS_OVFLW)
		},
	}
	cmdInspect.AddCommand(cmdInspectPostoverflow)

	return cmdInspect
}
