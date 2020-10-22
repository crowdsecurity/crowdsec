package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/davecgh/go-spew/spew"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/go-openapi/strfmt"
	qs "github.com/google/go-querystring/query"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	Scope      string
	Value      string
	Type       string
	Duration   string
	Reason     string
	DecisionID string
	NoSimu     bool
)
var DeleteAll bool
var Client *apiclient.ApiClient

func DecisionsToTable(alerts *models.GetAlertsResponse) error {
	if csConfig.Cscli.Output == "raw" {
		fmt.Printf("id,source,ip,reason,action,country,as,events_count,expiration,simulated\n")
		for _, alertItem := range *alerts {
			for _, decisionItem := range alertItem.Decisions {
				fmt.Printf("%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
					decisionItem.ID,
					*decisionItem.Origin,
					*decisionItem.Scope+":"+*decisionItem.Value,
					*decisionItem.Scenario,
					*decisionItem.Type,
					alertItem.Source.Cn,
					alertItem.Source.AsNumber+" "+alertItem.Source.AsName,
					*alertItem.EventsCount,
					*decisionItem.Duration,
					*decisionItem.Simulated)
			}
		}
	} else if csConfig.Cscli.Output == "json" {
		x, _ := json.MarshalIndent(alerts, "", " ")
		fmt.Printf("%s", string(x))
	} else if csConfig.Cscli.Output == "human" {

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"ID", "Source", "Scope:Value", "Reason", "Action", "Country", "AS", "Events", "expiration"})

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
		Use:     "decisions [action]",
		Short:   "Manage decisions",
		Long:    `Add/List/Delete decisions from LAPI`,
		Example: `cscli decisions [action] [filter]`,
		/*TBD example*/
		Args: cobra.MinimumNArgs(1),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			if csConfig.API.Client == nil {
				log.Fatalln("There is no configuration on 'api_client:'")
			}
			if csConfig.API.Client.Credentials == nil {
				log.Fatalf("Please provide credentials for the API in '%s'", csConfig.API.Client.CredentialsFilePath)
			}
			apiclient.BaseURL, err = url.Parse(csConfig.API.Client.Credentials.URL)
			if err != nil {
				log.Fatalf("failed to parse Local API URL %s : %v ", csConfig.API.Client.Credentials.URL, err.Error())
			}
			apiclient.UserAgent = fmt.Sprintf("crowdsec/%s", cwversion.VersionStr())

			password := strfmt.Password(csConfig.API.Client.Credentials.Password)
			t := &apiclient.JWTTransport{
				MachineID: &csConfig.API.Client.Credentials.Login,
				Password:  &password,
			}

			Client = apiclient.NewClient(t.Client())
			/*take care of shorthand options*/
			if err := manageCliDecisionAlerts(&IP, &Range, &Scope, &Value); err != nil {
				log.Fatalf("%s", err)
			}

		},
	}

	/*main filters : THESE FLAGS MUST REMAIN CONSISTENT WITH ALERTS FLAGS*/
	cmdDecisions.PersistentFlags().StringVarP(&Scope, "scope", "s", "ip", "scope to which the decision applies (ie. IP/Range/Username/Session/...)")
	cmdDecisions.PersistentFlags().StringVarP(&Value, "value", "v", "", "the value to match for in the specified scope")
	cmdDecisions.PersistentFlags().StringVarP(&Type, "type", "t", "", "type of decision")
	cmdDecisions.PersistentFlags().StringVar(&Scenario, "scenario", "", "Scenario")
	/*shorthand*/
	cmdDecisions.PersistentFlags().StringVarP(&IP, "ip", "i", "", "Source ip (shorthand for --scope ip --value <IP>)")
	cmdDecisions.PersistentFlags().StringVarP(&Range, "range", "r", "", "Range source ip (shorthand for --scope range --value <RANGE>)")
	/*secondary filters*/
	cmdDecisions.PersistentFlags().StringVar(&Since, "since", "", "since date (format is RFC3339: '2006-01-02T15:04:05+07:00'")
	cmdDecisions.PersistentFlags().StringVar(&Until, "until", "", "until date (format is RFC3339: '2006-01-02T15:04:05+07:00'")
	cmdDecisions.PersistentFlags().StringVar(&Source, "source", "", "matches the source (crowdsec)")
	/*for decisions only, not present from alerts*/
	cmdDecisions.PersistentFlags().BoolVar(&NoSimu, "no-simu", false, "exclude decisions in simulation mode")

	var cmdDecisionsList = &cobra.Command{
		Use:   "list [--ip ip] [--range range] [--scope scope] [--value value] [--type type]",
		Short: "List decisions from LAPI",
		/*TBD : redo Long + Example*/
		Args: cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			activeDecision := true

			filter := apiclient.AlertsListOpts{}
			filter.ActiveDecisionEquals = &activeDecision
			NoSimu = !NoSimu //revert the flag before setting it
			filter.IncludeSimulated = &NoSimu
			if Scope != "" {
				filter.ScopeEquals = &Scope
			}
			if Value != "" {
				filter.ValueEquals = &Value
			}
			if Type != "" {
				filter.TypeEquals = &Type
			}
			if IP != "" {
				filter.IPEquals = &IP
			}
			if Range != "" {
				filter.RangeEquals = &Range
			}

			alerts, _, err := Client.Alerts.List(context.Background(), filter)
			if err != nil {
				log.Printf("filter was : %s", spew.Sdump(filter))
				params, _ := qs.Values(filter)
				log.Printf("filter as : %s", params.Encode())
				log.Fatalf("Unable to list decisions : %v", err.Error())
			}

			err = DecisionsToTable(alerts)
			if err != nil {
				log.Printf("filter was : %s", spew.Sdump(filter))
				log.Fatalf("unable to list decisions : %v", err.Error())
			}
		},
	}
	cmdDecisions.AddCommand(cmdDecisionsList)

	var cmdDecisionsAdd = &cobra.Command{
		Use:   "add [--ip ip] [--range range] [--scope scope] [--value value] [--type type]",
		Short: "Add decision to LAPI",
		/*TBD : fix long and example*/
		Args: cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			var startIP, endIP int64
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

			if Value == "" {
				log.Errorf("Missing arguments, a value is required (--ip, --range or --scope and --value)")
				return
			}
			if Scope == types.Ip {
				startIP, endIP, err = database.GetIpsFromIpRange(Value + "/32")
				if err != nil {
					log.Fatalf("unable to parse IP or Range : '%s'", Value)
				}
			}
			if Scope == types.Range {
				startIP, endIP, err = database.GetIpsFromIpRange(Value)
				if err != nil {
					log.Fatalf("unable to parse IP or Range : '%s'", Value)
				}
				ipRange = Value
			}
			decision := models.Decision{
				Duration: &Duration,
				Scope:    &Scope,
				Value:    &Value,
				Type:     &Type,
				Scenario: &Reason,
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
				Message:         &Reason,
				ScenarioHash:    &empty,
				Scenario:        &Reason,
				ScenarioVersion: &empty,
				Simulated:       &simulated,
				Source: &models.Source{
					AsName:   empty,
					AsNumber: empty,
					Cn:       empty,
					IP:       ip,
					Range:    ipRange,
					Scope:    &Scope,
					Value:    &Value,
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
	cmdDecisionsAdd.Flags().StringVarP(&Duration, "duration", "d", "4h", "Decision duration (ie. 1h,4h,30m)")
	cmdDecisionsAdd.Flags().StringVarP(&Scope, "scope", "s", types.Ip, "Decision scope (ie. ip,range,username)")
	cmdDecisionsAdd.Flags().StringVarP(&Reason, "reason", "R", "", "Decision reason (ie. spam)")
	cmdDecisionsAdd.Flags().StringVarP(&Type, "type", "t", "ban", "Decision type (ie. ban,captcha,throttle)")

	cmdDecisions.AddCommand(cmdDecisionsAdd)

	var cmdDecisionsDelete = &cobra.Command{
		Use:   "delete [--ip ip] [--range range] [--scope scope] [--value value] [--type type] [--id [decision_id] [--all]",
		Short: "Delete decisions",
		/*TBD : refaire le Long/Example*/
		PreRun: func(cmd *cobra.Command, args []string) {
			if DecisionID != "" && (Scope != "" || Value != "" || Type != "" || IP != "" || Range != "" || DeleteAll == true) {
				cmd.Usage()
				log.Fatalln("--id parameter is used to delete uniq decision without filter")
			}
			if DeleteAll == false && (Scope == "" && Value == "" && Type == "" && DecisionID == "" && IP == "" && Range == "") {
				cmd.Usage()
				log.Fatalln("You need to specify a filter or use --all to delete all decisions")
			}
			if IP != "" && Range != "" {
				cmd.Usage()
				log.Fatalln("--ip and --range can't be used together")
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			var decisions *models.DeleteDecisionResponse

			filter := apiclient.DecisionsDeleteOpts{}
			if !DeleteAll {
				if Scope != "" {
					filter.Scope_equals = &Scope
				}
				if Value != "" {
					filter.Value_equals = &Value
				}
				if Type != "" {
					filter.Type_equals = &Type
				}
				if IP != "" {
					filter.IP_equals = &IP
				}
				if Range != "" {
					filter.Range_equals = &Range
				}
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
	cmdDecisionsDelete.Flags().StringVar(&DecisionID, "id", "", "decision id")
	cmdDecisionsDelete.Flags().BoolVar(&DeleteAll, "all", false, "delete all decisions")
	cmdDecisions.AddCommand(cmdDecisionsDelete)

	return cmdDecisions
}
