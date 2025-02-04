package cliitem

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clihub"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type cliHelp struct {
	// Example is required, the others have a default value
	// generated from the item type
	use     string
	short   string
	long    string
	example string
}

type configGetter func() *csconfig.Config

type cliItem struct {
	cfg           configGetter
	name          string // plural, as used in the hub index
	singular      string
	oneOrMore     string // parenthetical pluralizaion: "parser(s)"
	help          cliHelp
	installHelp   cliHelp
	removeHelp    cliHelp
	upgradeHelp   cliHelp
	inspectHelp   cliHelp
	inspectDetail func(item *cwhub.Item) error
	listHelp      cliHelp
}

func (cli cliItem) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               cmp.Or(cli.help.use, cli.name+" <action> [item]..."),
		Short:             cmp.Or(cli.help.short, "Manage hub "+cli.name),
		Long:              cli.help.long,
		Example:           cli.help.example,
		Args:              cobra.MinimumNArgs(1),
		Aliases:           []string{cli.singular},
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(cli.newInstallCmd())
	cmd.AddCommand(cli.newRemoveCmd())
	cmd.AddCommand(cli.newUpgradeCmd())
	cmd.AddCommand(cli.newInspectCmd())
	cmd.AddCommand(cli.newListCmd())

	return cmd
}

func (cli cliItem) list(args []string, all bool) error {
	cfg := cli.cfg()

	hub, err := require.Hub(cli.cfg(), log.StandardLogger())
	if err != nil {
		return err
	}

	items := make(map[string][]*cwhub.Item)

	items[cli.name], err = clihub.SelectItems(hub, cli.name, args, !all)
	if err != nil {
		return err
	}

	return clihub.ListItems(color.Output, cfg.Cscli.Color, []string{cli.name}, items, false, cfg.Cscli.Output)
}

func (cli cliItem) newListCmd() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:               cmp.Or(cli.listHelp.use, "list [item... | -a]"),
		Short:             cmp.Or(cli.listHelp.short, "List "+cli.oneOrMore),
		Long:              cmp.Or(cli.listHelp.long, "List of installed/available/specified "+cli.name),
		Example:           cli.listHelp.example,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			return cli.list(args, all)
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&all, "all", "a", false, "List disabled items as well")

	return cmd
}

func compInstalledItems(itemType string, args []string, toComplete string, cfg configGetter) ([]string, cobra.ShellCompDirective) {
	hub, err := require.Hub(cfg(), nil)
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}

	items := hub.GetInstalledByType(itemType, true)

	comp := make([]string, 0)

	for _, item := range items {
		if strings.Contains(item.Name, toComplete) {
			comp = append(comp, item.Name)
		}
	}

	cobra.CompDebugln(fmt.Sprintf("%s: %+v", itemType, comp), true)

	return comp, cobra.ShellCompDirectiveNoFileComp
}
