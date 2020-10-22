package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/go-openapi/strfmt"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

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
		Args:  cobra.MinimumNArgs(1),
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
		},
	}

	var alertListFilter = apiclient.AlertsListOpts{
		ScopeEquals:    new(string),
		ValueEquals:    new(string),
		ScenarioEquals: new(string),
		IPEquals:       new(string),
		RangeEquals:    new(string),
	}
	var cmdAlertsList = &cobra.Command{
		Use:   "list [filters]",
		Short: "List alerts",
		Example: `cscli alerts list
		cscli alerts list --ip 1.2.3.4
		cscli alerts list --range 1.2.3.0/24
		cscli alerts list -s crowdsecurity/ssh-bf`,
		Args: cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if err := manageCliDecisionAlerts(alertListFilter.IPEquals, alertListFilter.RangeEquals,
				alertListFilter.ScopeEquals, alertListFilter.ValueEquals); err != nil {
				cmd.Help()
				log.Fatalf("%s", err)
			}
			if *alertListFilter.ScopeEquals == "" {
				alertListFilter.ScopeEquals = nil
			}
			if *alertListFilter.ValueEquals == "" {
				alertListFilter.ValueEquals = nil
			}
			if *alertListFilter.ScenarioEquals == "" {
				alertListFilter.ScenarioEquals = nil
			}
			if *alertListFilter.IPEquals == "" {
				alertListFilter.IPEquals = nil
			}
			if *alertListFilter.RangeEquals == "" {
				alertListFilter.RangeEquals = nil
			}
			alerts, _, err := Client.Alerts.List(context.Background(), alertListFilter)
			if err != nil {
				log.Fatalf("Unable to list alerts : %v", err.Error())
			}

			err = AlertsToTable(alerts)
			if err != nil {
				log.Fatalf("unable to list alerts : %v", err.Error())
			}
		},
	}
	cmdAlertsList.Flags().SortFlags = false
	cmdAlertsList.Flags().StringVarP(alertListFilter.IPEquals, "ip", "i", "", "Source ip (shorthand for --scope ip --value <IP>)")
	cmdAlertsList.Flags().StringVarP(alertListFilter.ScenarioEquals, "scenario", "s", "", "the scenario (ie. crowdsecurity/ssh-bf)")
	cmdAlertsList.Flags().StringVarP(alertListFilter.RangeEquals, "range", "r", "", "Range source ip (shorthand for --scope range --value <RANGE>)")
	cmdAlertsList.Flags().StringVar(alertListFilter.ScopeEquals, "scope", "", "the scope (ie. ip,range)")
	cmdAlertsList.Flags().StringVarP(alertListFilter.ValueEquals, "value", "v", "", "the value to match for in the specified scope")
	cmdAlerts.AddCommand(cmdAlertsList)

	var ActiveDecision bool
	var AlertDeleteAll bool
	var alertDeleteFilter = apiclient.AlertsDeleteOpts{
		ScopeEquals:    new(string),
		ValueEquals:    new(string),
		ScenarioEquals: new(string),
		IPEquals:       new(string),
		RangeEquals:    new(string),
	}
	var cmdAlertsDelete = &cobra.Command{
		Use:   "delete [filters] [--all]",
		Short: "Delete alerts",
		Example: `cscli alerts delete --ip 1.2.3.4
		cscli alerts delete --range 1.2.3.0/24
		cscli alerts delete -s crowdsecurity/ssh-bf"`,
		Args: cobra.ExactArgs(0),
		PreRun: func(cmd *cobra.Command, args []string) {
			if AlertDeleteAll {
				return
			}
			if *alertDeleteFilter.ScopeEquals == "" && *alertDeleteFilter.ValueEquals == "" &&
				*alertDeleteFilter.ScenarioEquals == "" && *alertDeleteFilter.IPEquals == "" &&
				*alertDeleteFilter.RangeEquals == "" {
				cmd.Usage()
				log.Fatalln("At least one filter or --all must be specified")
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if err := manageCliDecisionAlerts(alertDeleteFilter.IPEquals, alertDeleteFilter.RangeEquals,
				alertDeleteFilter.ScopeEquals, alertDeleteFilter.ValueEquals); err != nil {
				cmd.Help()
				log.Fatalf("%s", err)
			}
			alertDeleteFilter.ActiveDecisionEquals = &ActiveDecision

			if *alertDeleteFilter.ScopeEquals == "" {
				alertDeleteFilter.ScopeEquals = nil
			}
			if *alertDeleteFilter.ValueEquals == "" {
				alertDeleteFilter.ValueEquals = nil
			}
			if *alertDeleteFilter.ScenarioEquals == "" {
				alertDeleteFilter.ScenarioEquals = nil
			}
			if *alertDeleteFilter.IPEquals == "" {
				alertDeleteFilter.IPEquals = nil
			}
			if *alertDeleteFilter.RangeEquals == "" {
				alertDeleteFilter.RangeEquals = nil
			}

			alerts, _, err := Client.Alerts.Delete(context.Background(), alertDeleteFilter)
			if err != nil {
				log.Fatalf("Unable to delete alerts : %v", err.Error())
			}
			log.Infof("%s alert(s) deleted", alerts.NbDeleted)

		},
	}
	cmdAlertsDelete.Flags().SortFlags = false
	cmdAlertsDelete.Flags().StringVar(alertDeleteFilter.ScopeEquals, "scope", "", "the scope (ie. ip,range)")
	cmdAlertsDelete.Flags().StringVarP(alertDeleteFilter.ValueEquals, "value", "v", "", "the value to match for in the specified scope")
	cmdAlertsDelete.Flags().StringVarP(alertDeleteFilter.ScenarioEquals, "scenario", "s", "", "the scenario (ie. crowdsecurity/ssh-bf)")
	cmdAlertsDelete.Flags().StringVarP(alertDeleteFilter.IPEquals, "ip", "i", "", "Source ip (shorthand for --scope ip --value <IP>)")
	cmdAlertsDelete.Flags().StringVarP(alertDeleteFilter.RangeEquals, "range", "r", "", "Range source ip (shorthand for --scope range --value <RANGE>)")
	cmdAlerts.AddCommand(cmdAlertsDelete)
	return cmdAlerts
}
