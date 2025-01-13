package climetrics

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/maptools"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/cstable"
)

func (cli *cliMetrics) list() error {
	type metricType struct {
		Type        string `json:"type"        yaml:"type"`
		Title       string `json:"title"       yaml:"title"`
		Description string `json:"description" yaml:"description"`
	}

	var allMetrics []metricType

	ms := NewMetricStore()
	for _, section := range maptools.SortedKeys(ms) {
		title, description := ms[section].Description()
		allMetrics = append(allMetrics, metricType{
			Type:        section,
			Title:       title,
			Description: description,
		})
	}

	outputFormat := cli.cfg().Cscli.Output

	switch outputFormat {
	case "human":
		out := color.Output
		t := cstable.New(out, cli.cfg().Cscli.Color).Writer
		t.AppendHeader(table.Row{"Type", "Title", "Description"})
		t.SetColumnConfigs([]table.ColumnConfig{
			{
				Name:        "Type",
				AlignHeader: text.AlignCenter,
			},
			{
				Name:        "Title",
				AlignHeader: text.AlignCenter,
			},
			{
				Name:             "Description",
				AlignHeader:      text.AlignCenter,
				WidthMax:         60,
				WidthMaxEnforcer: text.WrapSoft,
			},
		})

		t.Style().Options.SeparateRows = true

		for _, metric := range allMetrics {
			t.AppendRow(table.Row{metric.Type, metric.Title, metric.Description})
		}

		fmt.Fprintln(out, t.Render())
	case "json":
		x, err := json.MarshalIndent(allMetrics, "", " ")
		if err != nil {
			return fmt.Errorf("failed to serialize metric types: %w", err)
		}

		fmt.Println(string(x))
	default:
		return fmt.Errorf("output format '%s' not supported for this command", outputFormat)
	}

	return nil
}

func (cli *cliMetrics) newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "list",
		Short:             "List available types of metrics.",
		Long:              `List available types of metrics.`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.list()
		},
	}

	return cmd
}
