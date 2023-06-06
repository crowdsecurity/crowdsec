package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	"github.com/jszwec/csvutil"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/pkg/ptr"
	"github.com/crowdsecurity/go-cs-lib/pkg/version"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var Client *apiclient.ApiClient

func DecisionsToTable(alerts *models.GetAlertsResponse, printMachine bool) error {
	/*here we cheat a bit : to make it more readable for the user, we dedup some entries*/
	spamLimit := make(map[string]bool)
	skipped := 0

	for aIdx := 0; aIdx < len(*alerts); aIdx++ {
		alertItem := (*alerts)[aIdx]
		newDecisions := make([]*models.Decision, 0)
		for _, decisionItem := range alertItem.Decisions {
			spamKey := fmt.Sprintf("%t:%s:%s:%s", *decisionItem.Simulated, *decisionItem.Type, *decisionItem.Scope, *decisionItem.Value)
			if _, ok := spamLimit[spamKey]; ok {
				skipped++
				continue
			}
			spamLimit[spamKey] = true
			newDecisions = append(newDecisions, decisionItem)
		}
		alertItem.Decisions = newDecisions
	}
	if csConfig.Cscli.Output == "raw" {
		csvwriter := csv.NewWriter(os.Stdout)
		header := []string{"id", "source", "ip", "reason", "action", "country", "as", "events_count", "expiration", "simulated", "alert_id"}
		if printMachine {
			header = append(header, "machine")
		}
		err := csvwriter.Write(header)
		if err != nil {
			return err
		}
		for _, alertItem := range *alerts {
			for _, decisionItem := range alertItem.Decisions {
				raw := []string{
					fmt.Sprintf("%d", decisionItem.ID),
					*decisionItem.Origin,
					*decisionItem.Scope + ":" + *decisionItem.Value,
					*decisionItem.Scenario,
					*decisionItem.Type,
					alertItem.Source.Cn,
					alertItem.Source.GetAsNumberName(),
					fmt.Sprintf("%d", *alertItem.EventsCount),
					*decisionItem.Duration,
					fmt.Sprintf("%t", *decisionItem.Simulated),
					fmt.Sprintf("%d", alertItem.ID),
				}
				if printMachine {
					raw = append(raw, alertItem.MachineID)
				}

				err := csvwriter.Write(raw)
				if err != nil {
					return err
				}
			}
		}
		csvwriter.Flush()
	} else if csConfig.Cscli.Output == "json" {
		x, _ := json.MarshalIndent(alerts, "", " ")
		fmt.Printf("%s", string(x))
	} else if csConfig.Cscli.Output == "human" {
		if len(*alerts) == 0 {
			fmt.Println("No active decisions")
			return nil
		}
		decisionsTable(color.Output, alerts, printMachine)
		if skipped > 0 {
			fmt.Printf("%d duplicated entries skipped\n", skipped)
		}
	}
	return nil
}

func NewDecisionsCmd() *cobra.Command {
	var cmdDecisions = &cobra.Command{
		Use:     "decisions [action]",
		Short:   "Manage decisions",
		Long:    `Add/List/Delete/Import decisions from LAPI`,
		Example: `cscli decisions [action] [filter]`,
		Aliases: []string{"decision"},
		/*TBD example*/
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := csConfig.LoadAPIClient(); err != nil {
				return errors.Wrap(err, "loading api client")
			}
			password := strfmt.Password(csConfig.API.Client.Credentials.Password)
			apiurl, err := url.Parse(csConfig.API.Client.Credentials.URL)
			if err != nil {
				return errors.Wrapf(err, "parsing api url %s", csConfig.API.Client.Credentials.URL)
			}
			Client, err = apiclient.NewClient(&apiclient.Config{
				MachineID:     csConfig.API.Client.Credentials.Login,
				Password:      password,
				UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
				URL:           apiurl,
				VersionPrefix: "v1",
			})
			if err != nil {
				return errors.Wrap(err, "creating api client")
			}
			return nil
		},
	}

	cmdDecisions.AddCommand(NewDecisionsListCmd())
	cmdDecisions.AddCommand(NewDecisionsAddCmd())
	cmdDecisions.AddCommand(NewDecisionsDeleteCmd())
	cmdDecisions.AddCommand(NewDecisionsImportCmd())

	return cmdDecisions
}

func NewDecisionsListCmd() *cobra.Command {
	var filter = apiclient.AlertsListOpts{
		ValueEquals:    new(string),
		ScopeEquals:    new(string),
		ScenarioEquals: new(string),
		OriginEquals:   new(string),
		IPEquals:       new(string),
		RangeEquals:    new(string),
		Since:          new(string),
		Until:          new(string),
		TypeEquals:     new(string),
		IncludeCAPI:    new(bool),
		Limit:          new(int),
	}
	NoSimu := new(bool)
	contained := new(bool)
	var printMachine bool

	var cmdDecisionsList = &cobra.Command{
		Use:   "list [options]",
		Short: "List decisions from LAPI",
		Example: `cscli decisions list -i 1.2.3.4
cscli decisions list -r 1.2.3.0/24
cscli decisions list -s crowdsecurity/ssh-bf
cscli decisions list -t ban
`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			/*take care of shorthand options*/
			if err := manageCliDecisionAlerts(filter.IPEquals, filter.RangeEquals, filter.ScopeEquals, filter.ValueEquals); err != nil {
				log.Fatalf("%s", err)
			}
			filter.ActiveDecisionEquals = new(bool)
			*filter.ActiveDecisionEquals = true
			if NoSimu != nil && *NoSimu {
				filter.IncludeSimulated = new(bool)
			}
			/* nullify the empty entries to avoid bad filter */
			if *filter.Until == "" {
				filter.Until = nil
			} else if strings.HasSuffix(*filter.Until, "d") {
				/*time.ParseDuration support hours 'h' as bigger unit, let's make the user's life easier*/
				realDuration := strings.TrimSuffix(*filter.Until, "d")
				days, err := strconv.Atoi(realDuration)
				if err != nil {
					printHelp(cmd)
					log.Fatalf("Can't parse duration %s, valid durations format: 1d, 4h, 4h15m", *filter.Until)
				}
				*filter.Until = fmt.Sprintf("%d%s", days*24, "h")
			}

			if *filter.Since == "" {
				filter.Since = nil
			} else if strings.HasSuffix(*filter.Since, "d") {
				/*time.ParseDuration support hours 'h' as bigger unit, let's make the user's life easier*/
				realDuration := strings.TrimSuffix(*filter.Since, "d")
				days, err := strconv.Atoi(realDuration)
				if err != nil {
					printHelp(cmd)
					log.Fatalf("Can't parse duration %s, valid durations format: 1d, 4h, 4h15m", *filter.Until)
				}
				*filter.Since = fmt.Sprintf("%d%s", days*24, "h")
			}
			if *filter.IncludeCAPI {
				*filter.Limit = 0
			}
			if *filter.TypeEquals == "" {
				filter.TypeEquals = nil
			}
			if *filter.ValueEquals == "" {
				filter.ValueEquals = nil
			}
			if *filter.ScopeEquals == "" {
				filter.ScopeEquals = nil
			}
			if *filter.ScenarioEquals == "" {
				filter.ScenarioEquals = nil
			}
			if *filter.IPEquals == "" {
				filter.IPEquals = nil
			}
			if *filter.RangeEquals == "" {
				filter.RangeEquals = nil
			}

			if *filter.OriginEquals == "" {
				filter.OriginEquals = nil
			}

			if contained != nil && *contained {
				filter.Contains = new(bool)
			}

			alerts, _, err := Client.Alerts.List(context.Background(), filter)
			if err != nil {
				log.Fatalf("Unable to list decisions : %v", err)
			}

			err = DecisionsToTable(alerts, printMachine)
			if err != nil {
				log.Fatalf("unable to list decisions : %v", err)
			}
		},
	}
	cmdDecisionsList.Flags().SortFlags = false
	cmdDecisionsList.Flags().BoolVarP(filter.IncludeCAPI, "all", "a", false, "Include decisions from Central API")
	cmdDecisionsList.Flags().StringVar(filter.Since, "since", "", "restrict to alerts newer than since (ie. 4h, 30d)")
	cmdDecisionsList.Flags().StringVar(filter.Until, "until", "", "restrict to alerts older than until (ie. 4h, 30d)")
	cmdDecisionsList.Flags().StringVarP(filter.TypeEquals, "type", "t", "", "restrict to this decision type (ie. ban,captcha)")
	cmdDecisionsList.Flags().StringVar(filter.ScopeEquals, "scope", "", "restrict to this scope (ie. ip,range,session)")
	cmdDecisionsList.Flags().StringVar(filter.OriginEquals, "origin", "", fmt.Sprintf("the value to match for the specified origin (%s ...)", strings.Join(types.GetOrigins(), ",")))
	cmdDecisionsList.Flags().StringVarP(filter.ValueEquals, "value", "v", "", "restrict to this value (ie. 1.2.3.4,userName)")
	cmdDecisionsList.Flags().StringVarP(filter.ScenarioEquals, "scenario", "s", "", "restrict to this scenario (ie. crowdsecurity/ssh-bf)")
	cmdDecisionsList.Flags().StringVarP(filter.IPEquals, "ip", "i", "", "restrict to alerts from this source ip (shorthand for --scope ip --value <IP>)")
	cmdDecisionsList.Flags().StringVarP(filter.RangeEquals, "range", "r", "", "restrict to alerts from this source range (shorthand for --scope range --value <RANGE>)")
	cmdDecisionsList.Flags().IntVarP(filter.Limit, "limit", "l", 100, "number of alerts to get (use 0 to remove the limit)")
	cmdDecisionsList.Flags().BoolVar(NoSimu, "no-simu", false, "exclude decisions in simulation mode")
	cmdDecisionsList.Flags().BoolVarP(&printMachine, "machine", "m", false, "print machines that triggered decisions")
	cmdDecisionsList.Flags().BoolVar(contained, "contained", false, "query decisions contained by range")

	return cmdDecisionsList
}

func NewDecisionsAddCmd() *cobra.Command {
	var (
		addIP       string
		addRange    string
		addDuration string
		addValue    string
		addScope    string
		addReason   string
		addType     string
	)

	var cmdDecisionsAdd = &cobra.Command{
		Use:   "add [options]",
		Short: "Add decision to LAPI",
		Example: `cscli decisions add --ip 1.2.3.4
cscli decisions add --range 1.2.3.0/24
cscli decisions add --ip 1.2.3.4 --duration 24h --type captcha
cscli decisions add --scope username --value foobar
`,
		/*TBD : fix long and example*/
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			alerts := models.AddAlertsRequest{}
			origin := types.CscliOrigin
			capacity := int32(0)
			leakSpeed := "0"
			eventsCount := int32(1)
			empty := ""
			simulated := false
			startAt := time.Now().UTC().Format(time.RFC3339)
			stopAt := time.Now().UTC().Format(time.RFC3339)
			createdAt := time.Now().UTC().Format(time.RFC3339)

			/*take care of shorthand options*/
			if err := manageCliDecisionAlerts(&addIP, &addRange, &addScope, &addValue); err != nil {
				log.Fatalf("%s", err)
			}

			if addIP != "" {
				addValue = addIP
				addScope = types.Ip
			} else if addRange != "" {
				addValue = addRange
				addScope = types.Range
			} else if addValue == "" {
				printHelp(cmd)
				log.Fatalf("Missing arguments, a value is required (--ip, --range or --scope and --value)")
			}

			if addReason == "" {
				addReason = fmt.Sprintf("manual '%s' from '%s'", addType, csConfig.API.Client.Credentials.Login)
			}
			decision := models.Decision{
				Duration: &addDuration,
				Scope:    &addScope,
				Value:    &addValue,
				Type:     &addType,
				Scenario: &addReason,
				Origin:   &origin,
			}
			alert := models.Alert{
				Capacity:        &capacity,
				Decisions:       []*models.Decision{&decision},
				Events:          []*models.Event{},
				EventsCount:     &eventsCount,
				Leakspeed:       &leakSpeed,
				Message:         &addReason,
				ScenarioHash:    &empty,
				Scenario:        &addReason,
				ScenarioVersion: &empty,
				Simulated:       &simulated,
				//setting empty scope/value broke plugins, and it didn't seem to be needed anymore w/ latest papi changes
				Source: &models.Source{
					AsName:   empty,
					AsNumber: empty,
					Cn:       empty,
					IP:       addValue,
					Range:    "",
					Scope:    &addScope,
					Value:    &addValue,
				},
				StartAt:   &startAt,
				StopAt:    &stopAt,
				CreatedAt: createdAt,
			}
			alerts = append(alerts, &alert)

			_, _, err = Client.Alerts.Add(context.Background(), alerts)
			if err != nil {
				log.Fatal(err)
			}

			log.Info("Decision successfully added")
		},
	}

	cmdDecisionsAdd.Flags().SortFlags = false
	cmdDecisionsAdd.Flags().StringVarP(&addIP, "ip", "i", "", "Source ip (shorthand for --scope ip --value <IP>)")
	cmdDecisionsAdd.Flags().StringVarP(&addRange, "range", "r", "", "Range source ip (shorthand for --scope range --value <RANGE>)")
	cmdDecisionsAdd.Flags().StringVarP(&addDuration, "duration", "d", "4h", "Decision duration (ie. 1h,4h,30m)")
	cmdDecisionsAdd.Flags().StringVarP(&addValue, "value", "v", "", "The value (ie. --scope username --value foobar)")
	cmdDecisionsAdd.Flags().StringVar(&addScope, "scope", types.Ip, "Decision scope (ie. ip,range,username)")
	cmdDecisionsAdd.Flags().StringVarP(&addReason, "reason", "R", "", "Decision reason (ie. scenario-name)")
	cmdDecisionsAdd.Flags().StringVarP(&addType, "type", "t", "ban", "Decision type (ie. ban,captcha,throttle)")

	return cmdDecisionsAdd
}

func NewDecisionsDeleteCmd() *cobra.Command {
	var delFilter = apiclient.DecisionsDeleteOpts{
		ScopeEquals:    new(string),
		ValueEquals:    new(string),
		TypeEquals:     new(string),
		IPEquals:       new(string),
		RangeEquals:    new(string),
		ScenarioEquals: new(string),
		OriginEquals:   new(string),
	}
	var delDecisionId string
	var delDecisionAll bool
	contained := new(bool)

	var cmdDecisionsDelete = &cobra.Command{
		Use:               "delete [options]",
		Short:             "Delete decisions",
		DisableAutoGenTag: true,
		Aliases:           []string{"remove"},
		Example: `cscli decisions delete -r 1.2.3.0/24
cscli decisions delete -i 1.2.3.4
cscli decisions delete --id 42
cscli decisions delete --type captcha
`,
		/*TBD : refaire le Long/Example*/
		PreRun: func(cmd *cobra.Command, args []string) {
			if delDecisionAll {
				return
			}
			if *delFilter.ScopeEquals == "" && *delFilter.ValueEquals == "" &&
				*delFilter.TypeEquals == "" && *delFilter.IPEquals == "" &&
				*delFilter.RangeEquals == "" && *delFilter.ScenarioEquals == "" &&
				*delFilter.OriginEquals == "" && delDecisionId == "" {
				cmd.Usage()
				log.Fatalln("At least one filter or --all must be specified")
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			var decisions *models.DeleteDecisionResponse

			/*take care of shorthand options*/
			if err := manageCliDecisionAlerts(delFilter.IPEquals, delFilter.RangeEquals, delFilter.ScopeEquals, delFilter.ValueEquals); err != nil {
				log.Fatalf("%s", err)
			}
			if *delFilter.ScopeEquals == "" {
				delFilter.ScopeEquals = nil
			}
			if *delFilter.OriginEquals == "" {
				delFilter.OriginEquals = nil
			}
			if *delFilter.ValueEquals == "" {
				delFilter.ValueEquals = nil
			}
			if *delFilter.ScenarioEquals == "" {
				delFilter.ScenarioEquals = nil
			}
			if *delFilter.TypeEquals == "" {
				delFilter.TypeEquals = nil
			}
			if *delFilter.IPEquals == "" {
				delFilter.IPEquals = nil
			}
			if *delFilter.RangeEquals == "" {
				delFilter.RangeEquals = nil
			}
			if contained != nil && *contained {
				delFilter.Contains = new(bool)
			}

			if delDecisionId == "" {
				decisions, _, err = Client.Decisions.Delete(context.Background(), delFilter)
				if err != nil {
					log.Fatalf("Unable to delete decisions : %v", err)
				}
			} else {
				if _, err = strconv.Atoi(delDecisionId); err != nil {
					log.Fatalf("id '%s' is not an integer: %v", delDecisionId, err)
				}
				decisions, _, err = Client.Decisions.DeleteOne(context.Background(), delDecisionId)
				if err != nil {
					log.Fatalf("Unable to delete decision : %v", err)
				}
			}
			log.Infof("%s decision(s) deleted", decisions.NbDeleted)
		},
	}

	cmdDecisionsDelete.Flags().SortFlags = false
	cmdDecisionsDelete.Flags().StringVarP(delFilter.IPEquals, "ip", "i", "", "Source ip (shorthand for --scope ip --value <IP>)")
	cmdDecisionsDelete.Flags().StringVarP(delFilter.RangeEquals, "range", "r", "", "Range source ip (shorthand for --scope range --value <RANGE>)")
	cmdDecisionsDelete.Flags().StringVarP(delFilter.TypeEquals, "type", "t", "", "the decision type (ie. ban,captcha)")
	cmdDecisionsDelete.Flags().StringVarP(delFilter.ValueEquals, "value", "v", "", "the value to match for in the specified scope")
	cmdDecisionsDelete.Flags().StringVarP(delFilter.ScenarioEquals, "scenario", "s", "", "the scenario name (ie. crowdsecurity/ssh-bf)")
	cmdDecisionsDelete.Flags().StringVar(delFilter.OriginEquals, "origin", "", fmt.Sprintf("the value to match for the specified origin (%s ...)", strings.Join(types.GetOrigins(), ",")))

	cmdDecisionsDelete.Flags().StringVar(&delDecisionId, "id", "", "decision id")
	cmdDecisionsDelete.Flags().BoolVar(&delDecisionAll, "all", false, "delete all decisions")
	cmdDecisionsDelete.Flags().BoolVar(contained, "contained", false, "query decisions contained by range")

	return cmdDecisionsDelete
}

func NewDecisionsImportCmd() *cobra.Command {
	var (
		defaultDuration = "4h"
		defaultScope    = "ip"
		defaultType     = "ban"
		defaultReason   = "manual"
		importDuration  string
		importScope     string
		importReason    string
		importType      string
		importFile      string
		batchSize       int
	)

	var cmdDecisionImport = &cobra.Command{
		Use:   "import [options]",
		Short: "Import decisions from json or csv file",
		Long: "expected format :\n" +
			"csv  : any of duration,origin,reason,scope,type,value, with a header line\n" +
			`json : {"duration" : "24h", "origin" : "my-list", "reason" : "my_scenario", "scope" : "ip", "type" : "ban", "value" : "x.y.z.z"}`,
		DisableAutoGenTag: true,
		Example: `decisions.csv :
duration,scope,value
24h,ip,1.2.3.4

cscsli decisions import -i decisions.csv

decisions.json :
[{"duration" : "4h", "scope" : "ip", "type" : "ban", "value" : "1.2.3.4"}]
`,
		Run: func(cmd *cobra.Command, args []string) {
			if importFile == "" {
				log.Fatalf("Please provide a input file containing decisions with -i flag")
			}
			csvData, err := os.ReadFile(importFile)
			if err != nil {
				log.Fatalf("unable to open '%s': %s", importFile, err)
			}
			type decisionRaw struct {
				Duration string `csv:"duration,omitempty" json:"duration,omitempty"`
				Origin   string `csv:"origin,omitempty" json:"origin,omitempty"`
				Scenario string `csv:"reason,omitempty" json:"reason,omitempty"`
				Scope    string `csv:"scope,omitempty" json:"scope,omitempty"`
				Type     string `csv:"type,omitempty" json:"type,omitempty"`
				Value    string `csv:"value" json:"value"`
			}
			var decisionsListRaw []decisionRaw
			switch fileFormat := filepath.Ext(importFile); fileFormat {
			case ".json":
				if err := json.Unmarshal(csvData, &decisionsListRaw); err != nil {
					log.Fatalf("unable to unmarshall json: '%s'", err)
				}
			case ".csv":
				if err := csvutil.Unmarshal(csvData, &decisionsListRaw); err != nil {
					log.Fatalf("unable to unmarshall csv: '%s'", err)
				}
			default:
				log.Fatalf("file format not supported for '%s'. supported format are 'json' and 'csv'", importFile)
			}

			decisionsList := make([]*models.Decision, 0)
			for i, decisionLine := range decisionsListRaw {
				line := i + 2
				if decisionLine.Value == "" {
					log.Fatalf("please provide a 'value' in your csv line %d", line)
				}
				/*deal with defaults and cli-override*/
				if decisionLine.Duration == "" {
					decisionLine.Duration = defaultDuration
					log.Debugf("No 'duration' line %d, using default value: '%s'", line, defaultDuration)
				}
				if importDuration != "" {
					decisionLine.Duration = importDuration
					log.Debugf("'duration' line %d, using supplied value: '%s'", line, importDuration)
				}
				decisionLine.Origin = types.CscliImportOrigin

				if decisionLine.Scenario == "" {
					decisionLine.Scenario = defaultReason
					log.Debugf("No 'reason' line %d, using value: '%s'", line, decisionLine.Scenario)
				}
				if importReason != "" {
					decisionLine.Scenario = importReason
					log.Debugf("No 'reason' line %d, using supplied value: '%s'", line, importReason)
				}
				if decisionLine.Type == "" {
					decisionLine.Type = defaultType
					log.Debugf("No 'type' line %d, using default value: '%s'", line, decisionLine.Type)
				}
				if importType != "" {
					decisionLine.Type = importType
					log.Debugf("'type' line %d, using supplied value: '%s'", line, importType)
				}
				if decisionLine.Scope == "" {
					decisionLine.Scope = defaultScope
					log.Debugf("No 'scope' line %d, using default value: '%s'", line, decisionLine.Scope)
				}
				if importScope != "" {
					decisionLine.Scope = importScope
					log.Debugf("'scope' line %d, using supplied value: '%s'", line, importScope)
				}
				decision := models.Decision{
					Value:     ptr.Of(decisionLine.Value),
					Duration:  ptr.Of(decisionLine.Duration),
					Origin:    ptr.Of(decisionLine.Origin),
					Scenario:  ptr.Of(decisionLine.Scenario),
					Type:      ptr.Of(decisionLine.Type),
					Scope:     ptr.Of(decisionLine.Scope),
					Simulated: new(bool),
				}
				decisionsList = append(decisionsList, &decision)
			}
			alerts := models.AddAlertsRequest{}

			if batchSize > 0 {
				for i := 0; i < len(decisionsList); i += batchSize {
					end := i + batchSize
					if end > len(decisionsList) {
						end = len(decisionsList)
					}
					decisionBatch := decisionsList[i:end]
					importAlert := models.Alert{
						CreatedAt: time.Now().UTC().Format(time.RFC3339),
						Scenario:  ptr.Of(fmt.Sprintf("import %s : %d IPs", importFile, len(decisionBatch))),

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
						EventsCount:     ptr.Of(int32(len(decisionBatch))),
						Leakspeed:       ptr.Of(""),
						ScenarioHash:    ptr.Of(""),
						ScenarioVersion: ptr.Of(""),
						Decisions:       decisionBatch,
					}
					alerts = append(alerts, &importAlert)
				}
			} else {
				importAlert := models.Alert{
					CreatedAt: time.Now().UTC().Format(time.RFC3339),
					Scenario:  ptr.Of(fmt.Sprintf("import %s : %d IPs", importFile, len(decisionsList))),
					Message:   ptr.Of(""),
					Events:    []*models.Event{},
					Source: &models.Source{
						Scope: ptr.Of(""),
						Value: ptr.Of(""),
					},
					StartAt:         ptr.Of(time.Now().UTC().Format(time.RFC3339)),
					StopAt:          ptr.Of(time.Now().UTC().Format(time.RFC3339)),
					Capacity:        ptr.Of(int32(0)),
					Simulated:       ptr.Of(false),
					EventsCount:     ptr.Of(int32(len(decisionsList))),
					Leakspeed:       ptr.Of(""),
					ScenarioHash:    ptr.Of(""),
					ScenarioVersion: ptr.Of(""),
					Decisions:       decisionsList,
				}
				alerts = append(alerts, &importAlert)
			}

			if len(decisionsList) > 1000 {
				log.Infof("You are about to add %d decisions, this may take a while", len(decisionsList))
			}

			_, _, err = Client.Alerts.Add(context.Background(), alerts)
			if err != nil {
				log.Fatal(err)
			}
			log.Infof("%d decisions successfully imported", len(decisionsList))
		},
	}

	cmdDecisionImport.Flags().SortFlags = false
	cmdDecisionImport.Flags().StringVarP(&importFile, "input", "i", "", "Input file")
	cmdDecisionImport.Flags().StringVarP(&importDuration, "duration", "d", "", "Decision duration (ie. 1h,4h,30m)")
	cmdDecisionImport.Flags().StringVar(&importScope, "scope", types.Ip, "Decision scope (ie. ip,range,username)")
	cmdDecisionImport.Flags().StringVarP(&importReason, "reason", "R", "", "Decision reason (ie. scenario-name)")
	cmdDecisionImport.Flags().StringVarP(&importType, "type", "t", "", "Decision type (ie. ban,captcha,throttle)")
	cmdDecisionImport.Flags().IntVar(&batchSize, "batch", 0, "Split import in batches of N decisions")

	return cmdDecisionImport
}
