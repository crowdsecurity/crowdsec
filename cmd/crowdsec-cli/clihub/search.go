package clihub

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// itemMatchesTerms reports whether every term (case-insensitive) is a substring of the item name or description.
func itemMatchesTerms(item *cwhub.Item, terms []string) bool {
	haystack := strings.ToLower(item.Name + " " + item.Description)

	for _, term := range terms {
		if !strings.Contains(haystack, strings.ToLower(term)) {
			return false
		}
	}

	return true
}

func (cli *cliHub) search(out io.Writer, hub *cwhub.Hub, terms []string, statuses []string) error {
	cfg := cli.cfg()

	items := make(map[string][]*cwhub.Item)

	for _, itemType := range cwhub.ItemTypes {
		matched := make([]*cwhub.Item, 0)

		for _, item := range hub.GetItemsByType(itemType, true) {
			if itemMatchesTerms(item, terms) && itemMatchesStatus(item, statuses) {
				matched = append(matched, item)
			}
		}

		items[itemType] = matched
	}

	// human output is a single compact table; json/raw keep the per-type structure for scripts
	if cfg.Cscli.Output == "human" {
		merged := make([]*cwhub.Item, 0)
		for _, itemType := range cwhub.ItemTypes {
			merged = append(merged, items[itemType]...)
		}

		if len(merged) == 0 {
			fmt.Fprintln(out, "No matching items")
			return nil
		}

		listHubItemCompactTable(out, hub, cfg.Cscli.Color, merged, true)

		return nil
	}

	return ListItems(out, cfg.Cscli.Color, cwhub.ItemTypes, items, true, cfg.Cscli.Output)
}

func (cli *cliHub) newSearchCmd() *cobra.Command {
	var statuses []string

	cmd := &cobra.Command{
		Use:   "search [term]...",
		Short: "Search the local hub index by name and description",
		Long: `Search the local hub index.
An item matches when its name or description contains all the given terms.`,
		Example: `cscli hub search nginx
cscli hub search http cve
cscli hub search ssh --status installed`,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, terms []string) error {
			if err := validateStatuses(statuses); err != nil {
				return err
			}

			hub, err := require.Hub(cli.cfg(), log.StandardLogger())
			if err != nil {
				return err
			}

			return cli.search(color.Output, hub, terms, statuses)
		},
	}

	flags := cmd.Flags()
	flags.StringSliceVar(&statuses, "status", nil, "Filter by status ("+strings.Join(validItemStatuses, ", ")+")")

	_ = cmd.RegisterFlagCompletionFunc("status", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return validItemStatuses, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}
