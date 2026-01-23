package climachine

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/clientinfo"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// metricsInfo contains processed metrics data for JSON output
type metricsInfo struct {
	Acquisition []acquisitionMetric `json:"acquisition,omitempty"`
	Parsers     []parserMetric      `json:"parsers,omitempty"`
}

type acquisitionMetric struct {
	Source   string `json:"source"`
	Read     int    `json:"read"`
	Parsed   int    `json:"parsed"`
	Unparsed int    `json:"unparsed"`
}

type parserMetric struct {
	Source   string `json:"source"`
	Parser   string `json:"parser"`
	Stage    string `json:"stage"`
	Parsed   int    `json:"parsed"`
	Unparsed int    `json:"unparsed"`
}

func (cli *cliMachines) inspectHubHuman(out io.Writer, machine *ent.Machine) {
	state := machine.Hubstate

	if len(state) == 0 {
		fmt.Fprintln(os.Stdout, "No hub items found for this machine")
		return
	}

	// group state rows by type for multiple tables
	rowsByType := make(map[string][]table.Row)

	for itemType, items := range state {
		for _, item := range items {
			if _, ok := rowsByType[itemType]; !ok {
				rowsByType[itemType] = make([]table.Row, 0)
			}

			row := table.Row{item.Name, item.Status, item.Version}
			rowsByType[itemType] = append(rowsByType[itemType], row)
		}
	}

	for itemType, rows := range rowsByType {
		t := cstable.New(out, cli.cfg().Cscli.Color).Writer
		t.AppendHeader(table.Row{"Name", "Status", "Version"})
		t.SetTitle(itemType)
		t.AppendRows(rows)
		fmt.Fprintln(out, t.Render())
	}
}

func (cli *cliMachines) inspectHuman(out io.Writer, machine *ent.Machine) {
	t := cstable.New(out, cli.cfg().Cscli.Color).Writer

	t.SetTitle("Machine: " + machine.MachineId)

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})

	t.AppendRows([]table.Row{
		{"IP Address", machine.IpAddress},
		{"Created At", machine.CreatedAt},
		{"Last Update", machine.UpdatedAt},
		{"Last Heartbeat", machine.LastHeartbeat},
		{"Validated?", machine.IsValidated},
		{"CrowdSec version", machine.Version},
		{"OS", clientinfo.GetOSNameAndVersion(machine)},
		{"Auth type", machine.AuthType},
	})

	for dsName, dsCount := range machine.Datasources {
		t.AppendRow(table.Row{"Datasources", fmt.Sprintf("%s: %d", dsName, dsCount)})
	}

	for _, ff := range clientinfo.GetFeatureFlagList(machine) {
		t.AppendRow(table.Row{"Feature Flags", ff})
	}

	for _, coll := range machine.Hubstate[cwhub.COLLECTIONS] {
		t.AppendRow(table.Row{"Collections", coll.Name})
	}

	fmt.Fprintln(out, t.Render())
}

func (cli *cliMachines) inspectMetrics(out io.Writer, metrics []*ent.Metric) {
	// Create first table for global acquisition metrics (read, global_parsed, global_unparsed)
	cli.inspectAcquisitionMetrics(out, metrics)

	// Create second table for parser-specific metrics (parsed, unparsed)
	cli.inspectParserMetrics(out, metrics)
}

// processAcquisitionMetrics aggregates acquisition metrics data from raw metrics
func (*cliMachines) processAcquisitionMetrics(metrics []*ent.Metric) []acquisitionMetric {
	aggregatedMetrics := make(map[string]map[string]int)

	for _, metric := range metrics {
		var payload models.LogProcessorsMetrics

		if err := json.Unmarshal([]byte(metric.Payload), &payload); err != nil {
			continue
		}

		for _, detailedMetric := range payload.Metrics {
			if detailedMetric.Items == nil {
				continue
			}

			for _, item := range detailedMetric.Items {
				if item.Name == nil || item.Labels == nil || item.Value == nil {
					continue
				}

				metricName := *item.Name

				if metricName != "read" && metricName != "global_parsed" && metricName != "global_unparsed" {
					continue
				}

				datasourceType, hasDataSourceType := item.Labels["datasource_type"]
				source, hasSource := item.Labels["source"]
				acquisType, hasAcquisType := item.Labels["acquis_type"]

				if !hasDataSourceType || !hasSource || !hasAcquisType {
					continue
				}

				sourceID := fmt.Sprintf("%s:%s (%s)", datasourceType, source, acquisType)

				if aggregatedMetrics[sourceID] == nil {
					aggregatedMetrics[sourceID] = make(map[string]int)
				}

				var columnName string
				switch metricName {
				case "read":
					columnName = "read"
				case "global_parsed":
					columnName = "parsed"
				case "global_unparsed":
					columnName = "unparsed"
				}

				aggregatedMetrics[sourceID][columnName] += int(*item.Value)
			}
		}
	}

	// Convert to slice and sort
	var result []acquisitionMetric
	var sources []string
	for source := range aggregatedMetrics {
		sources = append(sources, source)
	}
	sort.Strings(sources)

	for _, source := range sources {
		metrics := aggregatedMetrics[source]
		result = append(result, acquisitionMetric{
			Source:   source,
			Read:     metrics["read"],
			Parsed:   metrics["parsed"],
			Unparsed: metrics["unparsed"],
		})
	}

	return result
}

func (cli *cliMachines) inspectAcquisitionMetrics(out io.Writer, metrics []*ent.Metric) {
	acquisitionMetrics := cli.processAcquisitionMetrics(metrics)

	if len(acquisitionMetrics) == 0 {
		return
	}

	t := cstable.New(out, cli.cfg().Cscli.Color).Writer

	t.SetTitle("Acquisition Metrics")
	t.AppendHeader(table.Row{"Source", "Read", "Parsed", "Unparsed"})

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})

	for _, metric := range acquisitionMetrics {
		t.AppendRow(table.Row{
			metric.Source,
			metric.Read,
			metric.Parsed,
			metric.Unparsed,
		})
	}

	fmt.Fprintln(out, t.Render())
}

// processParserMetrics aggregates parser metrics data from raw metrics
func (*cliMachines) processParserMetrics(metrics []*ent.Metric) []parserMetric {
	type parserInfo struct {
		stage   string
		name    string
		metrics map[string]int
	}
	aggregatedMetrics := make(map[string][]parserInfo)

	for _, metric := range metrics {
		var payload models.LogProcessorsMetrics

		if err := json.Unmarshal([]byte(metric.Payload), &payload); err != nil {
			continue
		}

		for _, detailedMetric := range payload.Metrics {
			for _, item := range detailedMetric.Items {
				if item.Name == nil || item.Labels == nil || item.Value == nil {
					continue
				}

				metricName := *item.Name

				if metricName != "parsed" && metricName != "unparsed" {
					continue
				}

				datasourceType := item.Labels["datasource_type"]
				source := item.Labels["source"]
				acquisType := item.Labels["acquis_type"]
				parserName := item.Labels["parser_name"]
				parserStage := item.Labels["parser_stage"]

				var sourceID string
				if datasourceType == "" && source == "" && acquisType == "" {
					// Postoverflows have lost the acquisition information, treat as a special case
					sourceID = "Postoverflows"
				} else {
					sourceID = fmt.Sprintf("%s:%s (%s)", datasourceType, source, acquisType)
				}

				var foundParser *parserInfo
				for i := range aggregatedMetrics[sourceID] {
					if aggregatedMetrics[sourceID][i].name == parserName {
						foundParser = &aggregatedMetrics[sourceID][i]
						break
					}
				}

				if foundParser == nil {
					newParser := parserInfo{
						stage:   parserStage,
						name:    parserName,
						metrics: make(map[string]int),
					}
					aggregatedMetrics[sourceID] = append(aggregatedMetrics[sourceID], newParser)
					foundParser = &aggregatedMetrics[sourceID][len(aggregatedMetrics[sourceID])-1]
				}

				foundParser.metrics[metricName] += int(*item.Value)
			}
		}
	}

	var result []parserMetric
	var sources []string
	for source := range aggregatedMetrics {
		sources = append(sources, source)
	}

	sort.Slice(sources, func(i, j int) bool {
		// Always put "Postoverflows" last
		if sources[i] == "Postoverflows" {
			return false
		}
		if sources[j] == "Postoverflows" {
			return true
		}
		return sources[i] < sources[j]
	})

	for _, source := range sources {
		parsers := aggregatedMetrics[source]

		// Sort parsers first by stage, then alphabetically by name
		sort.Slice(parsers, func(i, j int) bool {
			if parsers[i].stage != parsers[j].stage {
				return parsers[i].stage < parsers[j].stage
			}
			return parsers[i].name < parsers[j].name
		})

		for _, parser := range parsers {
			result = append(result, parserMetric{
				Source:   source,
				Parser:   parser.name,
				Stage:    parser.stage,
				Parsed:   parser.metrics["parsed"],
				Unparsed: parser.metrics["unparsed"],
			})
		}
	}

	return result
}

func (cli *cliMachines) inspectParserMetrics(out io.Writer, metrics []*ent.Metric) {
	parserMetrics := cli.processParserMetrics(metrics)

	if len(parserMetrics) == 0 {
		return
	}

	t := cstable.New(out, cli.cfg().Cscli.Color).Writer

	t.SetTitle("Parser Metrics")
	t.AppendHeader(table.Row{"Source", "Parser", "Parsed", "Unparsed"})

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})

	for _, metric := range parserMetrics {
		t.AppendRow(table.Row{
			metric.Source,
			fmt.Sprintf("%s/%s", metric.Stage, metric.Parser),
			metric.Parsed,
			metric.Unparsed,
		})
	}

	fmt.Fprintln(out, t.Render())
}

func (cli *cliMachines) inspect(machine *ent.Machine, metrics []*ent.Metric) error {
	out := color.Output
	outputFormat := cli.cfg().Cscli.Output

	switch outputFormat {
	case "human":
		cli.inspectHuman(out, machine)
		cli.inspectMetrics(out, metrics)
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		machineData := newMachineInfo(machine)
		metricsData := cli.processMetricsForJSON(metrics)

		result := struct {
			machineInfo
			Metrics metricsInfo `json:"metrics,omitempty"`
		}{
			machineInfo: machineData,
			Metrics:     metricsData,
		}

		if err := enc.Encode(result); err != nil {
			return errors.New("failed to serialize")
		}

		return nil
	default:
		return fmt.Errorf("output format '%s' not supported for this command", outputFormat)
	}

	return nil
}

func (cli *cliMachines) processMetricsForJSON(metrics []*ent.Metric) metricsInfo {
	result := metricsInfo{
		Acquisition: cli.processAcquisitionMetrics(metrics),
		Parsers:     cli.processParserMetrics(metrics),
	}
	return result
}

func (cli *cliMachines) inspectHub(machine *ent.Machine) error {
	out := color.Output

	switch cli.cfg().Cscli.Output {
	case "human":
		cli.inspectHubHuman(out, machine)
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		if err := enc.Encode(machine.Hubstate); err != nil {
			return errors.New("failed to serialize")
		}

		return nil
	case "raw":
		csvwriter := csv.NewWriter(out)

		err := csvwriter.Write([]string{"type", "name", "status", "version"})
		if err != nil {
			return fmt.Errorf("failed to write header: %w", err)
		}

		rows := make([][]string, 0)

		for itemType, items := range machine.Hubstate {
			for _, item := range items {
				rows = append(rows, []string{itemType, item.Name, item.Status, item.Version})
			}
		}

		for _, row := range rows {
			if err := csvwriter.Write(row); err != nil {
				return fmt.Errorf("failed to write raw output: %w", err)
			}
		}

		csvwriter.Flush()
	}

	return nil
}

func (cli *cliMachines) newInspectCmd() *cobra.Command {
	var showHub bool

	cmd := &cobra.Command{
		Use:               "inspect [machine_name]",
		Short:             "inspect a machine by name",
		Example:           `cscli machines inspect "machine1"`,
		Args:              args.ExactArgs(1),
		DisableAutoGenTag: true,
		ValidArgsFunction: cli.validMachineID,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			machineID := args[0]

			machine, err := cli.db.QueryMachineByID(ctx, machineID)
			if err != nil {
				return fmt.Errorf("unable to read machine data '%s': %w", machineID, err)
			}

			if showHub {
				return cli.inspectHub(machine)
			}

			machineMetrics, err := cli.db.GetLPUsageMetricsByMachineID(ctx, machineID, false)
			if err != nil {
				return fmt.Errorf("unable to read machine metrics '%s': %w", machineID, err)
			}
			return cli.inspect(machine, machineMetrics)
		},
	}

	flags := cmd.Flags()

	flags.BoolVarP(&showHub, "hub", "H", false, "show hub state")

	return cmd
}
