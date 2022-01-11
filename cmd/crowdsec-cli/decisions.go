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

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/go-openapi/strfmt"
	"github.com/jszwec/csvutil"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var Client *apiclient.ApiClient

var (
	defaultDuration = "4h"
	defaultScope    = "ip"
	defaultType     = "ban"
	defaultReason   = "manual"
)

func DecisionsToTable(alerts *models.GetAlertsResponse) error {
	/*here we cheat a bit : to make it more readable for the user, we dedup some entries*/
	var spamLimit map[string]bool = make(map[string]bool)
	var skipped = 0

	/*process in reverse order to keep the latest item only*/
	for aIdx := len(*alerts) - 1; aIdx >= 0; aIdx-- {
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
		err := csvwriter.Write([]string{"id", "source", "ip", "reason", "action", "country", "as", "events_count", "expiration", "simulated", "alert_id"})
		if err != nil {
			return err
		}
		for _, alertItem := range *alerts {
			for _, decisionItem := range alertItem.Decisions {
				err := csvwriter.Write([]string{
					fmt.Sprintf("%d", decisionItem.ID),
					*decisionItem.Origin,
					*decisionItem.Scope + ":" + *decisionItem.Value,
					*decisionItem.Scenario,
					*decisionItem.Type,
					alertItem.Source.Cn,
					alertItem.Source.AsNumber + " " + alertItem.Source.AsName,
					fmt.Sprintf("%d", *alertItem.EventsCount),
					*decisionItem.Duration,
					fmt.Sprintf("%t", *decisionItem.Simulated),
					fmt.Sprintf("%d", alertItem.ID),
				})
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

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"ID", "Source", "Scope:Value", "Reason", "Action", "Country", "AS", "Events", "expiration", "Alert ID"})

		if len(*alerts) == 0 {
			fmt.Println("No active decisions")
			return nil
		}

		for _, alertItem := range *alerts {
			for _, decisionItem := range alertItem.Decisions {
				if *alertItem.Simulated {
					*decisionItem.Type = fmt.Sprintf("(simul)%s", *decisionItem.Type)
				}
				table.Append([]string{
					strconv.Itoa(int(decisionItem.ID)),
					*decisionItem.Origin,
					*decisionItem.Scope + ":" + *decisionItem.Value,
					*decisionItem.Scenario,
					*decisionItem.Type,
					alertItem.Source.Cn,
					alertItem.Source.AsNumber + " " + alertItem.Source.AsName,
					strconv.Itoa(int(*alertItem.EventsCount)),
					*decisionItem.Duration,
					strconv.Itoa(int(alertItem.ID)),
				})
			}
		}
		table.Render() // Send output
		if skipped > 0 {
			fmt.Printf("%d duplicated entries skipped\n", skipped)
		}
	}
	return nil
}

func NewDecisionsCmd() *cobra.Command {
	/* ---- DECISIONS COMMAND */
	var cmdDecisions = &cobra.Command{
		Use:     "decisions [action]",
		Short:   "Manage decisions",
		Long:    `Add/List/Delete/Import decisions from LAPI`,
		Example: `cscli decisions [action] [filter]`,
		/*TBD example*/
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if err := csConfig.LoadAPIClient(); err != nil {
				log.Fatalf(err.Error())
			}
			if csConfig.API.Client == nil {
				log.Fatalln("There is no configuration on 'api_client:'")
			}
			if csConfig.API.Client.Credentials == nil {
				log.Fatalf("Please provide credentials for the API in '%s'", csConfig.API.Client.CredentialsFilePath)
			}
			password := strfmt.Password(csConfig.API.Client.Credentials.Password)
			apiurl, err := url.Parse(csConfig.API.Client.Credentials.URL)
			if err != nil {
				log.Fatalf("parsing api url ('%s'): %s", csConfig.API.Client.Credentials.URL, err)
			}
			Client, err = apiclient.NewClient(&apiclient.Config{
				MachineID:     csConfig.API.Client.Credentials.Login,
				Password:      password,
				UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				URL:           apiurl,
				VersionPrefix: "v1",
			})
			if err != nil {
				log.Fatalf("creating api client : %s", err)
			}
		},
	}

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
			/*nulify the empty entries to avoid bad filter*/
			if *filter.Until == "" {
				filter.Until = nil
			} else {
				/*time.ParseDuration support hours 'h' as bigger unit, let's make the user's life easier*/
				if strings.HasSuffix(*filter.Until, "d") {
					realDuration := strings.TrimSuffix(*filter.Until, "d")
					days, err := strconv.Atoi(realDuration)
					if err != nil {
						cmd.Help()
						log.Fatalf("Can't parse duration %s, valid durations format: 1d, 4h, 4h15m", *filter.Until)
					}
					*filter.Until = fmt.Sprintf("%d%s", days*24, "h")
				}
			}
			if *filter.Since == "" {
				filter.Since = nil
			} else {
				/*time.ParseDuration support hours 'h' as bigger unit, let's make the user's life easier*/
				if strings.HasSuffix(*filter.Since, "d") {
					realDuration := strings.TrimSuffix(*filter.Since, "d")
					days, err := strconv.Atoi(realDuration)
					if err != nil {
						cmd.Help()
						log.Fatalf("Can't parse duration %s, valid durations format: 1d, 4h, 4h15m", *filter.Until)
					}
					*filter.Since = fmt.Sprintf("%d%s", days*24, "h")
				}
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
				log.Fatalf("Unable to list decisions : %v", err.Error())
			}

			err = DecisionsToTable(alerts)
			if err != nil {
				log.Fatalf("unable to list decisions : %v", err.Error())
			}
		},
	}
	cmdDecisionsList.Flags().SortFlags = false
	cmdDecisionsList.Flags().BoolVarP(filter.IncludeCAPI, "all", "a", false, "Include decisions from Central API")
	cmdDecisionsList.Flags().StringVar(filter.Since, "since", "", "restrict to alerts newer than since (ie. 4h, 30d)")
	cmdDecisionsList.Flags().StringVar(filter.Until, "until", "", "restrict to alerts older than until (ie. 4h, 30d)")
	cmdDecisionsList.Flags().StringVarP(filter.TypeEquals, "type", "t", "", "restrict to this decision type (ie. ban,captcha)")
	cmdDecisionsList.Flags().StringVar(filter.ScopeEquals, "scope", "", "restrict to this scope (ie. ip,range,session)")
	cmdDecisionsList.Flags().StringVar(filter.OriginEquals, "origin", "", "restrict to this origin (ie. lists,CAPI,cscli)")
	cmdDecisionsList.Flags().StringVarP(filter.ValueEquals, "value", "v", "", "restrict to this value (ie. 1.2.3.4,userName)")
	cmdDecisionsList.Flags().StringVarP(filter.ScenarioEquals, "scenario", "s", "", "restrict to this scenario (ie. crowdsecurity/ssh-bf)")
	cmdDecisionsList.Flags().StringVarP(filter.IPEquals, "ip", "i", "", "restrict to alerts from this source ip (shorthand for --scope ip --value <IP>)")
	cmdDecisionsList.Flags().StringVarP(filter.RangeEquals, "range", "r", "", "restrict to alerts from this source range (shorthand for --scope range --value <RANGE>)")
	cmdDecisionsList.Flags().IntVarP(filter.Limit, "limit", "l", 100, "number of alerts to get (use 0 to remove the limit)")
	cmdDecisionsList.Flags().BoolVar(NoSimu, "no-simu", false, "exclude decisions in simulation mode")
	cmdDecisionsList.Flags().BoolVar(contained, "contained", false, "query decisions contained by range")

	cmdDecisions.AddCommand(cmdDecisionsList)

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
			var ip, ipRange string
			alerts := models.AddAlertsRequest{}
			origin := "cscli"
			capacity := int32(0)
			leakSpeed := "0"
			eventsCount := int32(1)
			empty := ""
			simulated := false
			startAt := time.Now().Format(time.RFC3339)
			stopAt := time.Now().Format(time.RFC3339)
			createdAt := time.Now().Format(time.RFC3339)

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
				cmd.Help()
				log.Errorf("Missing arguments, a value is required (--ip, --range or --scope and --value)")
				return
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
				Source: &models.Source{
					AsName:   empty,
					AsNumber: empty,
					Cn:       empty,
					IP:       ip,
					Range:    ipRange,
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
				log.Fatalf(err.Error())
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
	cmdDecisions.AddCommand(cmdDecisionsAdd)

	var delFilter = apiclient.DecisionsDeleteOpts{
		ScopeEquals: new(string),
		ValueEquals: new(string),
		TypeEquals:  new(string),
		IPEquals:    new(string),
		RangeEquals: new(string),
	}
	var delDecisionId string
	var delDecisionAll bool
	var cmdDecisionsDelete = &cobra.Command{
		Use:               "delete [options]",
		Short:             "Delete decisions",
		DisableAutoGenTag: true,
		Example: `cscli decisions delete -r 1.2.3.0/24
cscli decisions delete -i 1.2.3.4
cscli decisions delete -s crowdsecurity/ssh-bf
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
				*delFilter.RangeEquals == "" && delDecisionId == "" {
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
			if *delFilter.ValueEquals == "" {
				delFilter.ValueEquals = nil
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
					log.Fatalf("Unable to delete decisions : %v", err.Error())
				}
			} else {
				decisions, _, err = Client.Decisions.DeleteOne(context.Background(), delDecisionId)
				if err != nil {
					log.Fatalf("Unable to delete decision : %v", err.Error())
				}
			}
			log.Infof("%s decision(s) deleted", decisions.NbDeleted)
		},
	}

	cmdDecisionsDelete.Flags().SortFlags = false
	cmdDecisionsDelete.Flags().StringVarP(delFilter.IPEquals, "ip", "i", "", "Source ip (shorthand for --scope ip --value <IP>)")
	cmdDecisionsDelete.Flags().StringVarP(delFilter.RangeEquals, "range", "r", "", "Range source ip (shorthand for --scope range --value <RANGE>)")
	cmdDecisionsDelete.Flags().StringVar(&delDecisionId, "id", "", "decision id")
	cmdDecisionsDelete.Flags().StringVarP(delFilter.TypeEquals, "type", "t", "", "the decision type (ie. ban,captcha)")
	cmdDecisionsDelete.Flags().StringVarP(delFilter.ValueEquals, "value", "v", "", "the value to match for in the specified scope")
	cmdDecisionsDelete.Flags().BoolVar(&delDecisionAll, "all", false, "delete all decisions")
	cmdDecisionsDelete.Flags().BoolVar(contained, "contained", false, "query decisions contained by range")

	cmdDecisions.AddCommand(cmdDecisionsDelete)

	var (
		importDuration string
		importScope    string
		importReason   string
		importType     string
		importFile     string
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
				log.Fatalf("Please provide a input file contaning decisions with -i flag")
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
				decisionLine.Origin = "cscli-import"

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
					Value:     types.StrPtr(decisionLine.Value),
					Duration:  types.StrPtr(decisionLine.Duration),
					Origin:    types.StrPtr(decisionLine.Origin),
					Scenario:  types.StrPtr(decisionLine.Scenario),
					Type:      types.StrPtr(decisionLine.Type),
					Scope:     types.StrPtr(decisionLine.Scope),
					Simulated: new(bool),
				}
				decisionsList = append(decisionsList, &decision)
			}
			alerts := models.AddAlertsRequest{}
			importAlert := models.Alert{
				CreatedAt: time.Now().Format(time.RFC3339),
				Scenario:  types.StrPtr(fmt.Sprintf("add: %d IPs", len(decisionsList))),
				Message:   types.StrPtr(""),
				Events:    []*models.Event{},
				Source: &models.Source{
					Scope: types.StrPtr("cscli/manual-import"),
					Value: types.StrPtr(""),
				},
				StartAt:         types.StrPtr(time.Now().Format(time.RFC3339)),
				StopAt:          types.StrPtr(time.Now().Format(time.RFC3339)),
				Capacity:        types.Int32Ptr(0),
				Simulated:       types.BoolPtr(false),
				EventsCount:     types.Int32Ptr(int32(len(decisionsList))),
				Leakspeed:       types.StrPtr(""),
				ScenarioHash:    types.StrPtr(""),
				ScenarioVersion: types.StrPtr(""),
				Decisions:       decisionsList,
			}
			alerts = append(alerts, &importAlert)

			if len(decisionsList) > 1000 {
				log.Infof("You are about to add %d decisions, this may take a while", len(decisionsList))
			}

			_, _, err = Client.Alerts.Add(context.Background(), alerts)
			if err != nil {
				log.Fatalf(err.Error())
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
	cmdDecisions.AddCommand(cmdDecisionImport)

	return cmdDecisions
}
