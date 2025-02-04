package cliitem

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func (cli cliItem) inspect(ctx context.Context, args []string, url string, diff bool, rev bool, noMetrics bool) error {
	cfg := cli.cfg()

	if rev && !diff {
		return errors.New("--rev can only be used with --diff")
	}

	if url != "" {
		cfg.Cscli.PrometheusUrl = url
	}

	var contentProvider cwhub.ContentProvider

	if diff {
		contentProvider = require.HubDownloader(ctx, cfg)
	}

	hub, err := require.Hub(cfg, log.StandardLogger())
	if err != nil {
		return err
	}

	for _, name := range args {
		item := hub.GetItem(cli.name, name)
		if item == nil {
			return fmt.Errorf("can't find '%s' in %s", name, cli.name)
		}

		if diff {
			fmt.Println(cli.whyTainted(ctx, hub, contentProvider, item, rev))

			continue
		}

		if err = inspectItem(hub, item, !noMetrics, cfg.Cscli.Output, cfg.Cscli.PrometheusUrl, cfg.Cscli.Color); err != nil {
			return err
		}

		if cli.inspectDetail != nil {
			if err = cli.inspectDetail(item); err != nil {
				return err
			}
		}
	}

	return nil
}

// return the diff between the installed version and the latest version
func (cli cliItem) itemDiff(ctx context.Context, item *cwhub.Item, contentProvider cwhub.ContentProvider, reverse bool) (string, error) {
	if !item.State.Installed {
		return "", fmt.Errorf("'%s' is not installed", item.FQName())
	}

	dest, err := os.CreateTemp("", "cscli-diff-*")
	if err != nil {
		return "", fmt.Errorf("while creating temporary file: %w", err)
	}
	defer os.Remove(dest.Name())

	_, remoteURL, err := item.FetchContentTo(ctx, contentProvider, dest.Name())
	if err != nil {
		return "", err
	}

	latestContent, err := os.ReadFile(dest.Name())
	if err != nil {
		return "", fmt.Errorf("while reading %s: %w", dest.Name(), err)
	}

	localContent, err := os.ReadFile(item.State.LocalPath)
	if err != nil {
		return "", fmt.Errorf("while reading %s: %w", item.State.LocalPath, err)
	}

	file1 := item.State.LocalPath
	file2 := remoteURL
	content1 := string(localContent)
	content2 := string(latestContent)

	if reverse {
		file1, file2 = file2, file1
		content1, content2 = content2, content1
	}

	edits := myers.ComputeEdits(span.URIFromPath(file1), content1, content2)
	diff := gotextdiff.ToUnified(file1, file2, content1, edits)

	return fmt.Sprintf("%s", diff), nil
}

func (cli cliItem) whyTainted(ctx context.Context, hub *cwhub.Hub, contentProvider cwhub.ContentProvider, item *cwhub.Item, reverse bool) string {
	if !item.State.Installed {
		return fmt.Sprintf("# %s is not installed", item.FQName())
	}

	if !item.State.Tainted {
		return fmt.Sprintf("# %s is not tainted", item.FQName())
	}

	if len(item.State.TaintedBy) == 0 {
		return fmt.Sprintf("# %s is tainted but we don't know why. please report this as a bug", item.FQName())
	}

	ret := []string{
		fmt.Sprintf("# Let's see why %s is tainted.", item.FQName()),
	}

	for _, fqsub := range item.State.TaintedBy {
		ret = append(ret, fmt.Sprintf("\n-> %s\n", fqsub))

		sub, err := hub.GetItemFQ(fqsub)
		if err != nil {
			ret = append(ret, err.Error())
		}

		diff, err := cli.itemDiff(ctx, sub, contentProvider, reverse)
		if err != nil {
			ret = append(ret, err.Error())
		}

		if diff != "" {
			ret = append(ret, diff)
		} else if len(sub.State.TaintedBy) > 0 {
			taintList := strings.Join(sub.State.TaintedBy, ", ")
			if sub.FQName() == taintList {
				// hack: avoid message "item is tainted by itself"
				continue
			}

			ret = append(ret, fmt.Sprintf("# %s is tainted by %s", sub.FQName(), taintList))
		}
	}

	return strings.Join(ret, "\n")
}

func (cli cliItem) newInspectCmd() *cobra.Command {
	var (
		url       string
		diff      bool
		rev       bool
		noMetrics bool
	)

	cmd := &cobra.Command{
		Use:               cmp.Or(cli.inspectHelp.use, "inspect [item]..."),
		Short:             cmp.Or(cli.inspectHelp.short, "Inspect given "+cli.oneOrMore),
		Long:              cmp.Or(cli.inspectHelp.long, "Inspect the state of one or more "+cli.name),
		Example:           cli.inspectHelp.example,
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compInstalledItems(cli.name, args, toComplete, cli.cfg)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.inspect(cmd.Context(), args, url, diff, rev, noMetrics)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&url, "url", "u", "", "Prometheus url")
	flags.BoolVar(&diff, "diff", false, "Show diff with latest version (for tainted items)")
	flags.BoolVar(&rev, "rev", false, "Reverse diff output")
	flags.BoolVar(&noMetrics, "no-metrics", false, "Don't show metrics (when cscli.output=human)")

	return cmd
}

func inspectItem(hub *cwhub.Hub, item *cwhub.Item, wantMetrics bool, output string, prometheusURL string, wantColor string) error {
	// This is dirty...
	// We want to show current dependencies (from content), not latest (from index).
	// The item is modifed but after this function the whole hub should be thrown away.
	// A cleaner way would be to copy the struct first.
	item.Dependencies = item.CurrentDependencies()

	switch output {
	case "human", "raw":
		enc := yaml.NewEncoder(os.Stdout)
		enc.SetIndent(2)

		if err := enc.Encode(item); err != nil {
			return fmt.Errorf("unable to encode item: %w", err)
		}
	case "json":
		b, err := json.MarshalIndent(*item, "", "  ")
		if err != nil {
			return fmt.Errorf("unable to serialize item: %w", err)
		}

		fmt.Print(string(b))
	}

	if output != "human" {
		return nil
	}

	if item.State.Tainted {
		fmt.Println()
		fmt.Printf(`This item is tainted. Use "%s %s inspect --diff %s" to see why.`, filepath.Base(os.Args[0]), item.Type, item.Name)
		fmt.Println()
	}

	if wantMetrics {
		fmt.Printf("\nCurrent metrics: \n")

		if err := showMetrics(prometheusURL, hub, item, wantColor); err != nil {
			return err
		}
	}

	return nil
}
