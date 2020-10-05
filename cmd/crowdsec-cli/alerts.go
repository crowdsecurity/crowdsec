package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/go-openapi/strfmt"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var Scenario, AlertID, IP, Range, Since, Until, Source string
var ActiveDecision bool

func AlertsToTable(alerts *models.GetAlertsResponse) error {
	if csConfig.Cscli.Output == "raw" {
		fmt.Printf("id,Scope/Value,reason,country,as,events_count,created_at\n")
		for _, alertItem := range *alerts {
			var scenarioVersion string
			if alertItem.ScenarioVersion == nil {
				scenarioVersion = "N/A"
			}
			fmt.Printf("%v,%v,%v,%v,%v,%v,%v\n",
				alertItem.ID,
				*alertItem.Source.Scope+":"+*alertItem.Source.Value,
				fmt.Sprintf("%s (%s)", *alertItem.Scenario, scenarioVersion),
				alertItem.Source.Cn,
				alertItem.Source.AsNumber+" "+alertItem.Source.AsName,
				*alertItem.EventsCount,
				alertItem.CreatedAt)
		}
	} else if csConfig.Cscli.Output == "json" {
		x, _ := json.MarshalIndent(alerts, "", " ")
		fmt.Printf("%s", string(x))
	} else if csConfig.Cscli.Output == "human" {

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"ID", "Scope:Value", "reason", "country", "as", "events_count", "created_at"})

		if len(*alerts) == 0 {
			fmt.Println("No active decisions")
			return nil
		}

		for _, alertItem := range *alerts {
			var scenarioVersion string
			if alertItem.ScenarioVersion == nil {
				scenarioVersion = "N/A"
			}

			table.Append([]string{
				strconv.Itoa(int(alertItem.ID)),
				*alertItem.Source.Scope + ":" + *alertItem.Source.Value,
				fmt.Sprintf("%s (%s)", *alertItem.Scenario, scenarioVersion),
				alertItem.Source.Cn,
				alertItem.Source.AsNumber + " " + alertItem.Source.AsName,
				strconv.Itoa(int(*alertItem.EventsCount)),
				alertItem.CreatedAt,
			})
		}
		table.Render() // Send output
	}
	return nil
}

func NewAlertsCmd() *cobra.Command {
	/* ---- ALERTS COMMAND */
	var cmdAlerts = &cobra.Command{
		Use:   "alerts [action]",
		Short: "Manage alerts",
		Long: `
Alerts Management.

To list/add/delete alerts
`,
		Example: `cscli alerts [action] [filter]`,
		Args:    cobra.MinimumNArgs(1),
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

			password := strfmt.Password(csConfig.API.Client.Credentials.Password)
			t := &apiclient.JWTTransport{
				MachineID: &csConfig.API.Client.Credentials.Login,
				Password:  &password,
			}

			Client = apiclient.NewClient(t.Client())
		},
	}

	var cmdAlertsList = &cobra.Command{
		Use:     "list [filter]",
		Short:   "List alerts",
		Long:    `List alerts from the LAPI`,
		Example: `cscli alerts list --scope ip --value 1.2.3.4 --type ban"`,
		Args:    cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			var err error

			filter := apiclient.AlertsListOpts{}
			//			filter.ActiveDecisionEquals = &ActiveDecision

			if Scope != "" {
				filter.ScopeEquals = &Scope
			}
			if Value != "" {
				filter.ValueEquals = &Value
			}
			if Type != "" {
				filter.TypeEquals = &Type
			}
			if Scenario != "" {
				filter.ScenarioEquals = &Scenario
			}

			if IP != "" {
				filter.IPEquals = &IP
			}

			if Range != "" {
				filter.RangeEquals = &Range
			}

			if Since != "" {
				filter.SinceEquals = &Since
			}

			if Until != "" {
				filter.UntilEquals = &Until
			}

			if Source != "" {
				filter.SourceEquals = &Source
			}

			alerts, _, err := Client.Alerts.List(context.Background(), filter)
			if err != nil {
				log.Fatalf("Unable to list alerts : %v", err.Error())
			}

			err = AlertsToTable(alerts)
			if err != nil {
				log.Fatalf("unable to list alerts : %v", err.Error())
			}
		},
	}
	cmdAlertsList.Flags().StringVar(&Scope, "scope", "", "scope to which the decision applies (ie. IP/Range/Username/Session/...)")
	cmdAlertsList.Flags().StringVar(&Value, "value", "", "the value to match for in the specified scope")
	cmdAlertsList.Flags().StringVar(&Type, "type", "", "type of decision")
	cmdAlertsList.Flags().StringVar(&Scenario, "scenario", "", "Scenario")
	cmdAlertsList.Flags().StringVar(&IP, "ip", "", "Source ip")
	cmdAlertsList.Flags().StringVar(&Range, "range", "", "Range source ip")
	cmdAlertsList.Flags().StringVar(&Since, "since", "", "since date (format is RFC3339: '2006-01-02T15:04:05+07:00'")
	cmdAlertsList.Flags().StringVar(&Until, "until", "", "until date (format is RFC3339: '2006-01-02T15:04:05+07:00'")
	cmdAlertsList.Flags().StringVar(&Source, "source", "", "matches the source (crowdsec)")
	cmdAlerts.AddCommand(cmdAlertsList)

	var cmdAlertsDelete = &cobra.Command{
		Use:     "delete [filter]",
		Short:   "Delete alerts",
		Long:    `Delete alerts from the LAPI`,
		Example: `cscli alerts delete --scope ip --value 1.2.3.4 --type ban --active_decision"`,
		Args:    cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var err error

			filter := apiclient.AlertsDeleteOpts{}
			filter.ActiveDecisionEquals = &ActiveDecision

			if Scope != "" {
				filter.ScopeEquals = &Scope
			}
			if Value != "" {
				filter.ValueEquals = &Value
			}
			if Type != "" {
				filter.TypeEquals = &Type
			}
			if Scenario != "" {
				filter.ScenarioEquals = &Scenario
			}

			if IP != "" {
				filter.IPEquals = &IP
			}

			if Range != "" {
				filter.RangeEquals = &Range
			}

			if Since != "" {
				filter.SinceEquals = &Since
			}

			if Until != "" {
				filter.SinceEquals = &Until
			}

			if Source != "" {
				filter.SourceEquals = &Source
			}

			if Scope == "" && Value == "" && Type == "" && Scenario == "" && IP == "" && Range == "" && Until == "" && Source == "" {
				log.Infof("No alert deleted")
				return
			}

			alerts, _, err := Client.Alerts.Delete(context.Background(), filter)
			if err != nil {
				log.Fatalf("Unable to delete alerts : %v", err.Error())
			}
			log.Infof("%s alert(s) deleted", alerts.NbDeleted)

		},
	}
	cmdAlertsDelete.Flags().StringVar(&Scope, "scope", "", "scope to which the decision applies (ie. IP/Range/Username/Session/...)")
	cmdAlertsDelete.Flags().StringVar(&Value, "value", "", "the value to match for in the specified scope")
	cmdAlertsDelete.Flags().StringVar(&Type, "type", "", "type of decision")
	cmdAlertsDelete.Flags().StringVar(&Scenario, "scenario", "", "Scenario")
	cmdAlertsDelete.Flags().StringVar(&IP, "ip", "", "Source ip")
	cmdAlertsDelete.Flags().StringVar(&Range, "range", "", "Range source ip")
	cmdAlertsDelete.Flags().StringVar(&Since, "since", "", "since date (format is RFC3339: '2006-01-02T15:04:05+07:00'")
	cmdAlertsDelete.Flags().StringVar(&Until, "until", "", "until date (format is RFC3339: '2006-01-02T15:04:05+07:00'")
	cmdAlertsDelete.Flags().StringVar(&Source, "source", "", "matches the source (crowdsec)")
	cmdAlerts.AddCommand(cmdAlertsDelete)

	return cmdAlerts
}
