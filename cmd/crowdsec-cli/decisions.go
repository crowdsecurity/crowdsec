package main

import (
	"context"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"net/url"
)

var Scope, Value, Type string

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
	}

	var cmdDecisionsList = &cobra.Command{
		Use:     "list [filter]",
		Short:   "List decisions",
		Long:    `List decisions from the LAPI`,
		Example: `cscli decisions list --scope ip --value 1.2.3.4 --type ban"`,
		Args:    cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, arg []string) {
			var Client *apiclient.ApiClient
			var err error

			apiclient.BaseURL, err = url.Parse(csConfig.LapiClient.Credentials.Url)
			if err != nil {
				log.Fatalf("failed to parse Local API URL %s : %v ", csConfig.LapiClient.Credentials.Url, err.Error())
			}

			filter := apiclient.AlertsListOpts{}
			if Scope != "" {
				filter.ScopeEquals = &Scope
			}
			if Value != "" {
				filter.ValueEquals = &Value
			}
			if Type != "" {
				filter.TypeEquals = &Type
			}

			password := strfmt.Password(csConfig.LapiClient.Credentials.Password)
			t := &apiclient.JWTTransport{
				MachineID: &csConfig.LapiClient.Credentials.Login,
				Password:  &password,
				Scenarios: []string{"aaaaaa", "bbbbb"},
			}

			Client = apiclient.NewClient(t.Client())

			alerts, _, err := Client.Alerts.List(context.Background(), filter)
			if err != nil {
				log.Fatalf("Unable to list decisions : %v", err.Error())
			}

			log.Infof("%v", alerts)
		},
	}
	cmdDecisionsList.Flags().StringVar(&Scope, "scope", "", "scope to which the decision applies (ie. IP/Range/Username/Session/...)")
	cmdDecisionsList.Flags().StringVar(&Value, "value", "", "the value to match for in the specified scope")
	cmdDecisionsList.Flags().StringVar(&Type, "type", "", "type of decision")
	cmdDecisions.AddCommand(cmdDecisionsList)

	return cmdDecisions
}
