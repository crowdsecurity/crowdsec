package climetrics

import (
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type configGetter func() *csconfig.Config

type cliMetrics struct {
	cfg configGetter
}

func New(cfg configGetter) *cliMetrics {
	return &cliMetrics{
		cfg: cfg,
	}
}

func (cli *cliMetrics) NewCommand() *cobra.Command {
	var (
		url    string
		noUnit bool
	)

	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Display crowdsec prometheus metrics.",
		Long:  `Fetch metrics from a Local API server and display them`,
		Example: `# Show all Metrics, skip empty tables (same as "cecli metrics show")
cscli metrics

# Show only some metrics, connect to a different url
cscli metrics --url http://lapi.local:6060/metrics show acquisition parsers

# List available metric types
cscli metrics list`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.show(cmd.Context(), nil, url, noUnit)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&url, "url", "u", "", "Prometheus url (http://<ip>:<port>/metrics)")
	flags.BoolVar(&noUnit, "no-unit", false, "Show the real number instead of formatted with units")

	cmd.AddCommand(cli.newShowCmd())
	cmd.AddCommand(cli.newListCmd())

	return cmd
}
