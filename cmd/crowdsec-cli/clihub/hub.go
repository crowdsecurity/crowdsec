package clihub

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/reload"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/hubops"
)

type configGetter = func() *csconfig.Config

type cliHub struct {
	cfg configGetter
}

func New(cfg configGetter) *cliHub {
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
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(cli.newListCmd())
	cmd.AddCommand(cli.newUpdateCmd())
	cmd.AddCommand(cli.newUpgradeCmd())
	cmd.AddCommand(cli.newTypesCmd())

	return cmd
}

func (cli *cliHub) List(out io.Writer, hub *cwhub.Hub, all bool) error {
	cfg := cli.cfg()

	for _, v := range hub.Warnings {
		fmt.Fprintln(os.Stderr, v)
	}

	for _, line := range hub.ItemStats() {
		fmt.Fprintln(os.Stderr, line)
	}

	items := make(map[string][]*cwhub.Item)

	var err error

	for _, itemType := range cwhub.ItemTypes {
		items[itemType], err = SelectItems(hub, itemType, nil, !all)
		if err != nil {
			return err
		}
	}

	err = ListItems(out, cfg.Cscli.Color, cwhub.ItemTypes, items, true, cfg.Cscli.Output)
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
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			hub, err := require.Hub(cli.cfg(), log.StandardLogger())
			if err != nil {
				return err
			}

			return cli.List(color.Output, hub, all)
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&all, "all", "a", false, "List all available items, including those not installed")

	return cmd
}

func (cli *cliHub) update(ctx context.Context, withContent bool) error {
	local := cli.cfg().Hub
	// don't use require.Hub because if there is no index file, it would fail
	hub, err := cwhub.NewHub(local, log.StandardLogger())
	if err != nil {
		return err
	}

	indexProvider := require.HubDownloader(ctx, cli.cfg())

	updated, err := hub.Update(ctx, indexProvider, withContent)
	if err != nil {
		return fmt.Errorf("failed to update hub: %w", err)
	}

	if !updated && (log.StandardLogger().Level >= log.InfoLevel) {
		fmt.Println("Nothing to do, the hub index is up to date.")
	}

	if err := hub.Load(); err != nil {
		return fmt.Errorf("failed to load hub: %w", err)
	}

	for _, v := range hub.Warnings {
		fmt.Fprintln(os.Stderr, v)
	}

	return nil
}

func (cli *cliHub) newUpdateCmd() *cobra.Command {
	withContent := false

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Download the latest index (catalog of available configurations)",
		Long: `
Fetches the .index.json file from the hub, containing the list of available configs.
`,
		Example: `# Download the last version of the index file.
cscli hub update

# Download a 4x bigger version with all item contents (effectively pre-caching item downloads, but not data files).
cscli hub update --with-content`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Flags().Changed("with-content") {
				return cli.update(cmd.Context(), withContent)
			}
			return cli.update(cmd.Context(), cli.cfg().Cscli.HubWithContent)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&withContent, "with-content", false, "Download index with embedded item content")

	return cmd
}

func (cli *cliHub) upgrade(ctx context.Context, interactive bool, dryRun bool, force bool) error {
	cfg := cli.cfg()

	hub, err := require.Hub(cfg, log.StandardLogger())
	if err != nil {
		return err
	}

	plan := hubops.NewActionPlan(hub)

	contentProvider := require.HubDownloader(ctx, cfg)

	for _, itemType := range cwhub.ItemTypes {
		for _, item := range hub.GetInstalledByType(itemType, true) {
			if err := plan.AddCommand(hubops.NewDownloadCommand(item, contentProvider, force)); err != nil {
				return err
			}
		}
	}

	if err := plan.AddCommand(hubops.NewDataRefreshCommand(force)); err != nil {
		return err
	}

	showPlan := (log.StandardLogger().Level >= log.InfoLevel)
	verbosePlan := (cfg.Cscli.Output == "raw")

	if err := plan.Execute(ctx, interactive, dryRun, showPlan, verbosePlan); err != nil {
		return err
	}

	if msg := reload.UserMessage(); msg != "" && plan.ReloadNeeded {
		fmt.Println("\n" + msg)
	}

	return nil
}

func (cli *cliHub) newUpgradeCmd() *cobra.Command {
	var (
		interactive bool
		dryRun      bool
		force       bool
	)

	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade all configurations to their latest version",
		Long: `
Upgrade all configs installed from Crowdsec Hub. Run 'sudo cscli hub update' if you want the latest versions available.
`,
		Example: `# Upgrade all the collections, scenarios etc. to the latest version in the downloaded index. Update data files too.
cscli hub upgrade

# Upgrade tainted items as well; force re-download of data files.
cscli hub upgrade --force

# Prompt for confirmation if running in an interactive terminal; otherwise, the option is ignored.
cscli hub upgrade --interactive
cscli hub upgrade -i`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.upgrade(cmd.Context(), interactive, dryRun, force)
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&interactive, "interactive", "i", false, "Ask for confirmation before proceeding")
	flags.BoolVar(&dryRun, "dry-run", false, "Don't install or remove anything; print the execution plan")
	flags.BoolVar(&force, "force", false, "Force upgrade: overwrite tainted and outdated items; always update data files")
	cmd.MarkFlagsMutuallyExclusive("interactive", "dry-run")

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
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.types()
		},
	}

	return cmd
}
