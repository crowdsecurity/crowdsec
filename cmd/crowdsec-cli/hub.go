package main

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type cliHub struct{}

func NewCLIHub() *cliHub {
	return &cliHub{}
}

func (cli cliHub) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hub [action]",
		Short: "Manage hub index",
		Long: `Hub management

List/update parsers/scenarios/postoverflows/collections from [Crowdsec Hub](https://hub.crowdsec.net).
The Hub is managed by cscli, to get the latest hub files from [Crowdsec Hub](https://hub.crowdsec.net), you need to update.`,
		Example: `cscli hub list
cscli hub update
cscli hub upgrade`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(cli.NewListCmd())
	cmd.AddCommand(cli.NewUpdateCmd())
	cmd.AddCommand(cli.NewUpgradeCmd())
	cmd.AddCommand(cli.NewTypesCmd())

	return cmd
}

func (cli cliHub) list(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	all, err := flags.GetBool("all")
	if err != nil {
		return err
	}

	hub, err := require.Hub(csConfig, nil, log.StandardLogger())
	if err != nil {
		return err
	}

	for _, v := range hub.Warnings {
		log.Info(v)
	}

	for _, line := range hub.ItemStats() {
		log.Info(line)
	}

	items := make(map[string][]*cwhub.Item)

	for _, itemType := range cwhub.ItemTypes {
		items[itemType], err = selectItems(hub, itemType, nil, !all)
		if err != nil {
			return err
		}
	}

	err = listItems(color.Output, cwhub.ItemTypes, items, true)
	if err != nil {
		return err
	}

	return nil
}

func (cli cliHub) NewListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "list [-a]",
		Short:             "List all installed configurations",
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE:              cli.list,
	}

	flags := cmd.Flags()
	flags.BoolP("all", "a", false, "List disabled items as well")

	return cmd
}

func (cli cliHub) update(cmd *cobra.Command, args []string) error {
	local := csConfig.Hub
	remote := require.RemoteHub(csConfig)

	// don't use require.Hub because if there is no index file, it would fail
	hub, err := cwhub.NewHub(local, remote, true, log.StandardLogger())
	if err != nil {
		return fmt.Errorf("failed to update hub: %w", err)
	}

	for _, v := range hub.Warnings {
		log.Info(v)
	}

	return nil
}

func (cli cliHub) NewUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Download the latest index (catalog of available configurations)",
		Long: `
Fetches the .index.json file from the hub, containing the list of available configs.
`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE:              cli.update,
	}

	return cmd
}

func (cli cliHub) upgrade(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	force, err := flags.GetBool("force")
	if err != nil {
		return err
	}

	hub, err := require.Hub(csConfig, require.RemoteHub(csConfig), log.StandardLogger())
	if err != nil {
		return err
	}

	for _, itemType := range cwhub.ItemTypes {
		items, err := hub.GetInstalledItems(itemType)
		if err != nil {
			return err
		}

		updated := 0

		log.Infof("Upgrading %s", itemType)

		for _, item := range items {
			didUpdate, err := item.Upgrade(force)
			if err != nil {
				return err
			}
			if didUpdate {
				updated++
			}
		}

		log.Infof("Upgraded %d %s", updated, itemType)
	}

	return nil
}

func (cli cliHub) NewUpgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade all configurations to their latest version",
		Long: `
Upgrade all configs installed from Crowdsec Hub. Run 'sudo cscli hub update' if you want the latest versions available.
`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE:              cli.upgrade,
	}

	flags := cmd.Flags()
	flags.Bool("force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmd
}

func (cli cliHub) types(cmd *cobra.Command, args []string) error {
	switch csConfig.Cscli.Output {
	case "human":
		s, err := yaml.Marshal(cwhub.ItemTypes)
		if err != nil {
			return err
		}
		fmt.Print(string(s))
	case "json":
		jsonStr, err := json.Marshal(cwhub.ItemTypes)
		if err != nil {
			return err
		}
		fmt.Println(string(jsonStr))
	case "raw":
		for _, itemType := range cwhub.ItemTypes {
			fmt.Println(itemType)
		}
	}
	return nil
}

func (cli cliHub) NewTypesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "types",
		Short: "List supported item types",
		Long: `
List the types of supported hub items.
`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE:              cli.types,
	}

	return cmd
}
