package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/go-openapi/strfmt"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var Scope, Value, Type, DecisionID string
var DeleteAll bool
var Client *apiclient.ApiClient

func AlertsToTable(alerts *models.GetAlertsResponse) error {
	if csConfig.Cscli.Output == "raw" {
		fmt.Printf("id,source,ip,reason,action,country,as,events_count,expiration\n")
		for _, alertItem := range *alerts {
			for _, decisionItem := range alertItem.Decisions {
				fmt.Printf("%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
					decisionItem.ID,
					*decisionItem.Origin,
					*decisionItem.Scope+":"+*decisionItem.Target,
					*decisionItem.Scenario,
					*decisionItem.Type,
					alertItem.Source.Cn,
					alertItem.Source.AsNumber+" "+alertItem.Source.AsName,
					*alertItem.EventsCount,
					*decisionItem.Duration)
			}
		}
	} else if csConfig.Cscli.Output == "json" {
		x, _ := json.MarshalIndent(alerts, "", " ")
		fmt.Printf("%s", string(x))
	} else if csConfig.Cscli.Output == "human" {

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"ID", "Source", "Target", "Reason", "Action", "Country", "AS", "Events", "Expiration"})

		if len(*alerts) == 0 {
			fmt.Println("No active decisions")
			return nil
		}

		for _, alertItem := range *alerts {
			for _, decisionItem := range alertItem.Decisions {
				table.Append([]string{
					strconv.Itoa(int(decisionItem.ID)),
					*decisionItem.Origin,
					*decisionItem.Scope + ":" + *decisionItem.Target,
					*decisionItem.Scenario,
					*decisionItem.Type,
					alertItem.Source.Cn,
					alertItem.Source.AsNumber + " " + alertItem.Source.AsName,
					strconv.Itoa(int(*alertItem.EventsCount)),
					*decisionItem.Duration,
				})
			}
		}
		table.Render() // Send output
	}
	return nil
}

func NewDecisionsCmd() *cobra.Command {
	/* ---- DECISIONS COMMAND */
	var cmdDecisions = &cobra.Command{
		Use:   "decisions [action]",
		Short: "Manage decisions",
		Long: `
Decisions Management.

To list/add/delete decisions
`,
		Example: `cscli decisions [action] [filter]`,
		Args:    cobra.MinimumNArgs(1),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			if csConfig.LapiClient == nil {
				log.Fatalln("There is no configuration on 'api_client:'")
			}
			apiclient.BaseURL, err = url.Parse(csConfig.LapiClient.Credentials.Url)
			if err != nil {
				log.Fatalf("failed to parse Local API URL %s : %v ", csConfig.LapiClient.Credentials.Url, err.Error())
			}

			scenarios := []string{}
			for _, scenario := range cwhub.GetItemMap(cwhub.SCENARIOS) {
				scenarios = append(scenarios, scenario.Name)
			}

			password := strfmt.Password(csConfig.LapiClient.Credentials.Password)
			t := &apiclient.JWTTransport{
				MachineID: &csConfig.LapiClient.Credentials.Login,
				Password:  &password,
				Scenarios: scenarios,
			}

			Client = apiclient.NewClient(t.Client())
		},
	}

	var cmdDecisionsList = &cobra.Command{
		Use:     "list --scope [scope] --value [value] --type [type]",
		Short:   "List decisions",
		Long:    `List decisions from the LAPI`,
		Example: `cscli decisions list --scope ip --value 1.2.3.4 --type ban"`,
		Args:    cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			activeDecision := true

			filter := apiclient.AlertsListOpts{}
			filter.ActiveDecisionEquals = &activeDecision
			if Scope != "" {
				filter.ScopeEquals = &Scope
			}
			if Value != "" {
				filter.ValueEquals = &Value
			}
			if Type != "" {
				filter.TypeEquals = &Type
			}

			alerts, _, err := Client.Alerts.List(context.Background(), filter)
			if err != nil {
				log.Fatalf("Unable to list decisions : %v", err.Error())
			}

			err = AlertsToTable(alerts)
			if err != nil {
				log.Fatalf("unable to list decisions : %v", err.Error())
			}
		},
	}
	cmdDecisionsList.Flags().StringVar(&Scope, "scope", "", "scope to which the decision applies (ie. IP/Range/Username/Session/...)")
	cmdDecisionsList.Flags().StringVar(&Value, "value", "", "the value to match for in the specified scope")
	cmdDecisionsList.Flags().StringVar(&Type, "type", "", "type of decision")
	cmdDecisions.AddCommand(cmdDecisionsList)

	var cmdDecisionsAdd = &cobra.Command{
		Use:   "add <type> <scope> <target> <duration> <reason>",
		Short: "Add decision",
		Long: `
Add decision to the LAPI
Args :
<type>     : type of the decision (ban, captcha, or something custom)
<scope>    : scope of the decision (ip, range, username, group etc..)
<target>   : target of the decision depending of the scope
<duration> : must be [time.ParseDuration](https://golang.org/pkg/time/#ParseDuration), expressed in s/m/h.
<reason>   : reason of the decision
`,
		Example: `cscli decisions add ban ip 1.2.3.4 12h "is manually blacklisted"`,
		Args:    cobra.MinimumNArgs(5),
		Run: func(cmd *cobra.Command, args []string) {
			var startIP, endIP int64
			var err error
			var ip, ipRange string
			alerts := models.AddAlertsRequest{}
			origin := "cscli"
			ttype := args[0]
			scope := args[1]
			target := args[2]
			duration := args[3]
			reason := strings.Join(args[4:], " ")
			capacity := int32(0)
			leakSpeed := "0"
			eventsCount := int32(1)
			empty := ""
			simulated := false
			startAt := time.Now().Format(time.RFC3339)
			stopAt := time.Now().Format(time.RFC3339)

			if scope == "ip" {
				isValidIP := database.IsIpv4(target)
				if !isValidIP {
					log.Fatalf("unable to parse IP or Range : '%s'", target)
				}
				startIP, endIP, err = database.GetIpsFromIpRange(target + "/32")
				if err != nil {
					log.Fatalf("unable to parse IP or Range : '%s'", target)
				}
				ip = target
			}
			if scope == "range" {
				startIP, endIP, err = database.GetIpsFromIpRange(target)
				if err != nil {
					log.Fatalf("unable to parse IP or Range : '%s'", target)
				}
				ipRange = target
			}

			decision := models.Decision{
				Duration: &duration,
				Scope:    &scope,
				Target:   &target,
				Type:     &ttype,
				Scenario: &reason,
				Origin:   &origin,
				StartIP:  startIP,
				EndIP:    endIP,
			}
			alert := models.Alert{
				Capacity:        &capacity,
				Decisions:       []*models.Decision{&decision},
				Events:          []*models.Event{},
				EventsCount:     &eventsCount,
				Leakspeed:       &leakSpeed,
				MachineID:       csConfig.LapiClient.Credentials.Login,
				Message:         &reason,
				ScenarioHash:    &empty,
				Scenario:        &empty,
				ScenarioVersion: &empty,
				Simulated:       &simulated,
				Source: &models.Source{
					AsName:   empty,
					AsNumber: empty,
					Cn:       empty,
					IP:       ip,
					Range:    ipRange,
					Scope:    &scope,
					Value:    &target,
				},
				StartAt: &startAt,
				StopAt:  &stopAt,
			}
			alerts = append(alerts, &alert)

			_, _, err = Client.Alerts.Add(context.Background(), alerts)
			if err != nil {
				log.Fatalf(err.Error())
			}

			log.Info("Decision successfully added")
		},
	}
	cmdDecisions.AddCommand(cmdDecisionsAdd)

	var cmdDecisionsDelete = &cobra.Command{
		Use:   "delete (--scope [scope] --value [value] --type [type] | --id [decision_id] | --all)",
		Short: "Delete decisions",
		Long: `
Delete decisions from the LAPI
You can delete uniq decision by id (--id), with other filters (--scope/--value/--type) or all decisions with --all
/!\ You can't use filters (--scope/--value/--type) with --id or --all
`,
		Example: `
		cscli decisions delete --scope ip --value 1.2.3.4 --type ban"
		cscli decisions delete --id 1"
		`,
		PreRun: func(cmd *cobra.Command, args []string) {
			if DecisionID != "" && (Scope != "" || Value != "" || Type != "" || DeleteAll == true) {
				cmd.Usage()
				log.Fatalln("--id parameter is used to delete uniq decision without filter")
			}
			if DeleteAll == false && (Scope == "" && Value == "" && Type == "" && DecisionID == "") {
				cmd.Usage()
				log.Fatalln("You need to specify a filter or use --all to delete all decisions")
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			var decisions *models.DeleteDecisionResponse

			filter := apiclient.DecisionsDeleteOpts{}
			if Scope != "" {
				filter.Scope_equals = &Scope
			}
			if Value != "" {
				filter.Value_equals = &Value
			}
			if Type != "" {
				filter.Type_equals = &Type
			}

			if DecisionID == "" {
				decisions, _, err = Client.Decisions.Delete(context.Background(), filter)
				if err != nil {
					log.Fatalf("Unable to delete decisions : %v", err.Error())
				}
			} else {
				decisions, _, err = Client.Decisions.DeleteOne(context.Background(), DecisionID)
				if err != nil {
					log.Fatalf("Unable to delete decision : %v", err.Error())
				}
			}

			log.Infof("%s decision(s) deleted", decisions.NbDeleted)
		},
	}
	cmdDecisionsDelete.Flags().StringVar(&Scope, "scope", "", "scope to which the decision applies (ie. IP/Range/Username/Session/...)")
	cmdDecisionsDelete.Flags().StringVar(&Value, "value", "", "the value to match for in the specified scope")
	cmdDecisionsDelete.Flags().StringVar(&Type, "type", "", "type of decision")
	cmdDecisionsDelete.Flags().StringVar(&DecisionID, "id", "", "decision id")
	cmdDecisionsDelete.Flags().BoolVar(&DeleteAll, "all", false, "delete all decisions")
	cmdDecisions.AddCommand(cmdDecisionsDelete)

	return cmdDecisions
}
