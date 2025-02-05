package climetrics

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/maptools"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
)

var (
	ErrMissingConfig   = errors.New("prometheus section missing, can't show metrics")
	ErrMetricsDisabled = errors.New("prometheus is not enabled, can't show metrics")
)

func (cli *cliMetrics) show(ctx context.Context, sections []string, url string, noUnit bool) error {
	cfg := cli.cfg()

	if url != "" {
		cfg.Cscli.PrometheusUrl = url
	}

	if cfg.Prometheus == nil {
		return ErrMissingConfig
	}

	if !cfg.Prometheus.Enabled {
		return ErrMetricsDisabled
	}

	ms := NewMetricStore()

	db, err := require.DBClient(ctx, cfg.DbConfig)
	if err != nil {
		log.Warnf("unable to open database: %s", err)
	}

	if err := ms.Fetch(ctx, cfg.Cscli.PrometheusUrl, db); err != nil {
		log.Warn(err)
	}

	// any section that we don't have in the store is an error
	for _, section := range sections {
		if _, ok := ms[section]; !ok {
			return fmt.Errorf("unknown metrics type: %s", section)
		}
	}

	return ms.Format(color.Output, cfg.Cscli.Color, sections, cfg.Cscli.Output, noUnit)
}

// expandAlias returns a list of sections. The input can be a list of sections or alias.
func expandAlias(args []string) []string {
	ret := []string{}

	for _, section := range args {
		switch section {
		case "engine":
			ret = append(ret, "acquisition", "parsers", "scenarios", "stash", "whitelists")
		case "lapi":
			ret = append(ret, "alerts", "decisions", "lapi", "lapi-bouncer", "lapi-decisions", "lapi-machine")
		case "appsec":
			ret = append(ret, "appsec-engine", "appsec-rule")
		default:
			ret = append(ret, section)
		}
	}

	return ret
}

func (cli *cliMetrics) newShowCmd() *cobra.Command {
	var (
		url    string
		noUnit bool
	)

	cmd := &cobra.Command{
		Use:   "show [type]...",
		Short: "Display all or part of the available metrics.",
		Long:  `Fetch metrics from a Local API server and display them, optionally filtering on specific types.`,
		Example: `# Show all Metrics, skip empty tables
cscli metrics show

# Use an alias: "engine", "lapi" or "appsec" to show a group of metrics
cscli metrics show engine

# Show some specific metrics, show empty tables, connect to a different url
cscli metrics show acquisition parsers scenarios stash --url http://lapi.local:6060/metrics

# To list available metric types, use "cscli metrics list"
cscli metrics list; cscli metrics list -o json

# Show metrics in json format
cscli metrics show acquisition parsers scenarios stash -o json`,
		// Positional args are optional
		DisableAutoGenTag: true,
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			ms := NewMetricStore()
			ret := []string{}
			for _, section := range maptools.SortedKeys(ms) {
				if !slices.Contains(args, section) && strings.Contains(section, toComplete) {
					ret = append(ret, section)
				}
			}

			return ret, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			args = expandAlias(args)
			return cli.show(cmd.Context(), args, url, noUnit)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&url, "url", "u", "", "Metrics url (http://<ip>:<port>/metrics)")
	flags.BoolVar(&noUnit, "no-unit", false, "Show the real number instead of formatted with units")

	return cmd
}
