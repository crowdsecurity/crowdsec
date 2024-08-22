package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type cliHub struct {
	cfg configGetter
}

func NewCLIHub(cfg configGetter) *cliHub {
	return &cliHub{
		cfg: cfg,
	}
}

func (cli *cliHub) NewCommand() *cobra.Command {
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

	cmd.AddCommand(cli.newListCmd())
	cmd.AddCommand(cli.newUpdateCmd())
	cmd.AddCommand(cli.newUpgradeCmd())
	cmd.AddCommand(cli.newTypesCmd())

	return cmd
}

func (cli *cliHub) list(all bool) error {
	cfg := cli.cfg()

	hub, err := require.Hub(cfg, nil, log.StandardLogger())
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

	err = listItems(color.Output, cfg.Cscli.Color, cwhub.ItemTypes, items, true, cfg.Cscli.Output)
	if err != nil {
		return err
	}

	return nil
}

func (cli *cliHub) newListCmd() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:               "list [-a]",
		Short:             "List all installed configurations",
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.list(all)
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&all, "all", "a", false, "List disabled items as well")

	return cmd
}

func (cli *cliHub) update(ctx context.Context) error {
	local := cli.cfg().Hub
	remote := require.RemoteHub(ctx, cli.cfg())

	// don't use require.Hub because if there is no index file, it would fail
	hub, err := cwhub.NewHub(local, remote, log.StandardLogger())
	if err != nil {
		return err
	}

	if err := hub.Update(ctx); err != nil {
		return fmt.Errorf("failed to update hub: %w", err)
	}

	if err := hub.Load(); err != nil {
		return fmt.Errorf("failed to load hub: %w", err)
	}

	for _, v := range hub.Warnings {
		log.Info(v)
	}

	return nil
}

func (cli *cliHub) newUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Download the latest index (catalog of available configurations)",
		Long: `
Fetches the .index.json file from the hub, containing the list of available configs.
`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.update(cmd.Context())
		},
	}

	return cmd
}

func (cli *cliHub) upgrade(ctx context.Context, force bool) error {
	hub, err := require.Hub(cli.cfg(), require.RemoteHub(ctx, cli.cfg()), log.StandardLogger())
	if err != nil {
		return err
	}

	for _, itemType := range cwhub.ItemTypes {
		updated := 0

		log.Infof("Upgrading %s", itemType)

		for _, item := range hub.GetInstalledByType(itemType, true) {
			didUpdate, err := item.Upgrade(ctx, force)
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

func (cli *cliHub) newUpgradeCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade all configurations to their latest version",
		Long: `
Upgrade all configs installed from Crowdsec Hub. Run 'sudo cscli hub update' if you want the latest versions available.
`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.upgrade(cmd.Context(), force)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&force, "force", false, "Force upgrade: overwrite tainted and outdated files")

	return cmd
}

func (cli *cliHub) types() error {
	switch cli.cfg().Cscli.Output {
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

func (cli *cliHub) newTypesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "types",
		Short: "List supported item types",
		Long: `
List the types of supported hub items.
`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.types()
		},
	}

	return cmd
}
