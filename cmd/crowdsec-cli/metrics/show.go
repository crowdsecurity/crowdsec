package metrics

import (
	"errors"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	ErrMissingConfig   = errors.New("prometheus section missing, can't show metrics")
	ErrMetricsDisabled = errors.New("prometheus is not enabled, can't show metrics")
)

func (cli *cliMetrics) show(sections []string, url string, noUnit bool) error {
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

	if err := ms.Fetch(cfg.Cscli.PrometheusUrl); err != nil {
		return err
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
		RunE: func(_ *cobra.Command, args []string) error {
			args = expandAlias(args)
			return cli.show(args, url, noUnit)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&url, "url", "u", "", "Metrics url (http://<ip>:<port>/metrics)")
	flags.BoolVar(&noUnit, "no-unit", false, "Show the real number instead of formatted with units")

	return cmd
}
