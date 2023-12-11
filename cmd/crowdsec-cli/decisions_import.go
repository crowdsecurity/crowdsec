package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jszwec/csvutil"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/slicetools"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// decisionRaw is only used to unmarshall json/csv decisions
type decisionRaw struct {
	Duration string `csv:"duration,omitempty" json:"duration,omitempty"`
	Scenario string `csv:"reason,omitempty"   json:"reason,omitempty"`
	Scope    string `csv:"scope,omitempty"    json:"scope,omitempty"`
	Type     string `csv:"type,omitempty"     json:"type,omitempty"`
	Value    string `csv:"value"              json:"value"`
}

func parseDecisionList(content []byte, format string) ([]decisionRaw, error) {
	ret := []decisionRaw{}

	switch format {
	case "values":
		log.Infof("Parsing values")
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			value := strings.TrimSpace(scanner.Text())
			ret = append(ret, decisionRaw{Value: value})
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("unable to parse values: '%s'", err)
		}
	case "json":
		log.Infof("Parsing json")
		if err := json.Unmarshal(content, &ret); err != nil {
			return nil, err
		}
	case "csv":
		log.Infof("Parsing csv")
		if err := csvutil.Unmarshal(content, &ret); err != nil {
			return nil, fmt.Errorf("unable to parse csv: '%s'", err)
		}
	default:
		return nil, fmt.Errorf("invalid format '%s', expected one of 'json', 'csv', 'values'", format)
	}

	return ret, nil
}


func (cli cliDecisions) runImport(cmd *cobra.Command, args []string) error  {
	flags := cmd.Flags()

	input, err := flags.GetString("input")
	if err != nil {
		return err
	}

	defaultDuration, err := flags.GetString("duration")
	if err != nil {
		return err
	}
	if defaultDuration == "" {
		return fmt.Errorf("--duration cannot be empty")
	}

	defaultScope, err := flags.GetString("scope")
	if err != nil {
		return err
	}
	if defaultScope == "" {
		return fmt.Errorf("--scope cannot be empty")
	}

	defaultReason, err := flags.GetString("reason")
	if err != nil {
		return err
	}
	if defaultReason == "" {
		return fmt.Errorf("--reason cannot be empty")
	}

	defaultType, err := flags.GetString("type")
	if err != nil {
		return err
	}
	if defaultType == "" {
		return fmt.Errorf("--type cannot be empty")
	}

	batchSize, err := flags.GetInt("batch")
	if err != nil {
		return err
	}

	format, err := flags.GetString("format")
	if err != nil {
		return err
	}

	var (
		content []byte
		fin	*os.File
	)

	// set format if the file has a json or csv extension
	if format == "" {
		if strings.HasSuffix(input, ".json") {
			format = "json"
		} else if strings.HasSuffix(input, ".csv") {
			format = "csv"
		}
	}

	if format == "" {
		return fmt.Errorf("unable to guess format from file extension, please provide a format with --format flag")
	}

	if input == "-" {
		fin = os.Stdin
		input = "stdin"
	} else {
		fin, err = os.Open(input)
		if err != nil {
			return fmt.Errorf("unable to open %s: %s", input, err)
		}
	}

	content, err = io.ReadAll(fin)
	if err != nil {
		return fmt.Errorf("unable to read from %s: %s", input, err)
	}

	decisionsListRaw, err := parseDecisionList(content, format)
	if err != nil {
		return err
	}

	decisions := make([]*models.Decision, len(decisionsListRaw))
	for i, d := range decisionsListRaw {
		if d.Value == "" {
			return fmt.Errorf("item %d: missing 'value'", i)
		}

		if d.Duration == "" {
			d.Duration = defaultDuration
			log.Debugf("item %d: missing 'duration', using default '%s'", i, defaultDuration)
		}

		if d.Scenario == "" {
			d.Scenario = defaultReason
			log.Debugf("item %d: missing 'reason', using default '%s'", i, defaultReason)
		}

		if d.Type == "" {
			d.Type = defaultType
			log.Debugf("item %d: missing 'type', using default '%s'", i, defaultType)
		}

		if d.Scope == "" {
			d.Scope = defaultScope
			log.Debugf("item %d: missing 'scope', using default '%s'", i, defaultScope)
		}

		decisions[i] = &models.Decision{
			Value:     ptr.Of(d.Value),
			Duration:  ptr.Of(d.Duration),
			Origin:    ptr.Of(types.CscliImportOrigin),
			Scenario:  ptr.Of(d.Scenario),
			Type:      ptr.Of(d.Type),
			Scope:     ptr.Of(d.Scope),
			Simulated: ptr.Of(false),
		}
	}

	if len(decisions) > 1000 {
		log.Infof("You are about to add %d decisions, this may take a while", len(decisions))
	}

	for _, chunk := range slicetools.Chunks(decisions, batchSize) {
		log.Debugf("Processing chunk of %d decisions", len(chunk))
		importAlert := models.Alert{
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
			Scenario:  ptr.Of(fmt.Sprintf("import %s: %d IPs", input, len(chunk))),

			Message: ptr.Of(""),
			Events:  []*models.Event{},
			Source: &models.Source{
				Scope: ptr.Of(""),
				Value: ptr.Of(""),
			},
			StartAt:         ptr.Of(time.Now().UTC().Format(time.RFC3339)),
			StopAt:          ptr.Of(time.Now().UTC().Format(time.RFC3339)),
			Capacity:        ptr.Of(int32(0)),
			Simulated:       ptr.Of(false),
			EventsCount:     ptr.Of(int32(len(chunk))),
			Leakspeed:       ptr.Of(""),
			ScenarioHash:    ptr.Of(""),
			ScenarioVersion: ptr.Of(""),
			Decisions:       chunk,
		}

		_, _, err = Client.Alerts.Add(context.Background(), models.AddAlertsRequest{&importAlert})
		if err != nil {
			return err
		}
	}

	log.Infof("Imported %d decisions", len(decisions))
	return nil
}


func (cli cliDecisions) NewImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import [options]",
		Short: "Import decisions from a file or pipe",
		Long: "expected format:\n" +
			"csv  : any of duration,reason,scope,type,value, with a header line\n" +
			"json :" + "`{" + `"duration" : "24h", "reason" : "my_scenario", "scope" : "ip", "type" : "ban", "value" : "x.y.z.z"` + "}`",
		DisableAutoGenTag: true,
		Example: `decisions.csv:
duration,scope,value
24h,ip,1.2.3.4

$ cscli decisions import -i decisions.csv

decisions.json:
[{"duration" : "4h", "scope" : "ip", "type" : "ban", "value" : "1.2.3.4"}]

The file format is detected from the extension, but can be forced with the --format option
which is required when reading from standard input.

Raw values, standard input:

$ echo "1.2.3.4" | cscli decisions import -i - --format values
`,
		RunE: cli.runImport,
	}

	flags := cmd.Flags()
	flags.SortFlags = false
	flags.StringP("input", "i", "", "Input file")
	flags.StringP("duration", "d", "4h", "Decision duration: 1h,4h,30m")
	flags.String("scope", types.Ip, "Decision scope: ip,range,username")
	flags.StringP("reason", "R", "manual", "Decision reason: <scenario-name>")
	flags.StringP("type", "t", "ban", "Decision type: ban,captcha,throttle")
	flags.Int("batch", 0, "Split import in batches of N decisions")
	flags.String("format", "", "Input format: 'json', 'csv' or 'values' (each line is a value, no headers)")

	cmd.MarkFlagRequired("input")

	return cmd
}
