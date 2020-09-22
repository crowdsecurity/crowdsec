package main

import (
	"context"
	"net/url"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var Scenario, AlertID string

func NewAlertsCmd() *cobra.Command {
	/* ---- DECISIONS COMMAND */
	var cmdAlerts = &cobra.Command{
		Use:   "alerts [action]",
		Short: "Manage alerts",
		Long: `
Alerts Management.

To list/add/delete decisions
`,
		Example: `cscli alerts [action] [filter]`,
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

	var cmdAlertsList = &cobra.Command{
		Use:     "list [filter]",
		Short:   "List alerts",
		Long:    `List alerts from the LAPI`,
		Example: `cscli alerts list --scope ip --value 1.2.3.4 --type ban"`,
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

			if Scenario != "" {
				filter.ScenarioEquals = &Scenario
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
	cmdAlerts.AddCommand(cmdAlertsList)

	return cmdAlerts
}
