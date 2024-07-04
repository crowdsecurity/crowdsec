package metrics

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

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

	switch cli.cfg().Cscli.Output {
	case "human":
		t := cstable.New(color.Output, cli.cfg().Cscli.Color)
		t.SetRowLines(true)
		t.SetHeaders("Type", "Title", "Description")

		for _, metric := range allMetrics {
			t.AddRow(metric.Type, metric.Title, metric.Description)
		}

		t.Render()
	case "json":
		x, err := json.MarshalIndent(allMetrics, "", " ")
		if err != nil {
			return fmt.Errorf("failed to marshal metric types: %w", err)
		}

		fmt.Println(string(x))
	case "raw":
		x, err := yaml.Marshal(allMetrics)
		if err != nil {
			return fmt.Errorf("failed to marshal metric types: %w", err)
		}

		fmt.Println(string(x))
	}

	return nil
}

func (cli *cliMetrics) newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "list",
		Short:             "List available types of metrics.",
		Long:              `List available types of metrics.`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.list()
		},
	}

	return cmd
}
