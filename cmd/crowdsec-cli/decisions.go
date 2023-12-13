package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/version"

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
		if *alerts == nil {
			// avoid returning "null" in `json"
			// could be cleaner if we used slice of alerts directly
			fmt.Println("[]")
			return nil
		}
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


type cliDecisions struct {}

func NewCLIDecisions() *cliDecisions {
	return &cliDecisions{}
}

func (cli cliDecisions) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
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
				return fmt.Errorf("loading api client: %w", err)
			}
			password := strfmt.Password(csConfig.API.Client.Credentials.Password)
			apiurl, err := url.Parse(csConfig.API.Client.Credentials.URL)
			if err != nil {
				return fmt.Errorf("parsing api url %s: %w", csConfig.API.Client.Credentials.URL, err)
			}
			Client, err = apiclient.NewClient(&apiclient.Config{
				MachineID:     csConfig.API.Client.Credentials.Login,
				Password:      password,
				UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
				URL:           apiurl,
				VersionPrefix: "v1",
			})
			if err != nil {
				return fmt.Errorf("creating api client: %w", err)
			}
			return nil
		},
	}

	cmd.AddCommand(cli.NewListCmd())
	cmd.AddCommand(cli.NewAddCmd())
	cmd.AddCommand(cli.NewDeleteCmd())
	cmd.AddCommand(cli.NewImportCmd())

	return cmd
}

func (cli cliDecisions) NewListCmd() *cobra.Command {
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

	cmd := &cobra.Command{
		Use:   "list [options]",
		Short: "List decisions from LAPI",
		Example: `cscli decisions list -i 1.2.3.4
cscli decisions list -r 1.2.3.0/24
cscli decisions list -s crowdsecurity/ssh-bf
cscli decisions list -t ban
`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			/*take care of shorthand options*/
			if err = manageCliDecisionAlerts(filter.IPEquals, filter.RangeEquals, filter.ScopeEquals, filter.ValueEquals); err != nil {
				return err
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
					return fmt.Errorf("can't parse duration %s, valid durations format: 1d, 4h, 4h15m", *filter.Until)
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
					return fmt.Errorf("can't parse duration %s, valid durations format: 1d, 4h, 4h15m", *filter.Since)
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
				return fmt.Errorf("unable to retrieve decisions: %w", err)
			}

			err = DecisionsToTable(alerts, printMachine)
			if err != nil {
				return fmt.Errorf("unable to print decisions: %w", err)
			}

			return nil
		},
	}
	cmd.Flags().SortFlags = false
	cmd.Flags().BoolVarP(filter.IncludeCAPI, "all", "a", false, "Include decisions from Central API")
	cmd.Flags().StringVar(filter.Since, "since", "", "restrict to alerts newer than since (ie. 4h, 30d)")
	cmd.Flags().StringVar(filter.Until, "until", "", "restrict to alerts older than until (ie. 4h, 30d)")
	cmd.Flags().StringVarP(filter.TypeEquals, "type", "t", "", "restrict to this decision type (ie. ban,captcha)")
	cmd.Flags().StringVar(filter.ScopeEquals, "scope", "", "restrict to this scope (ie. ip,range,session)")
	cmd.Flags().StringVar(filter.OriginEquals, "origin", "", fmt.Sprintf("the value to match for the specified origin (%s ...)", strings.Join(types.GetOrigins(), ",")))
	cmd.Flags().StringVarP(filter.ValueEquals, "value", "v", "", "restrict to this value (ie. 1.2.3.4,userName)")
	cmd.Flags().StringVarP(filter.ScenarioEquals, "scenario", "s", "", "restrict to this scenario (ie. crowdsecurity/ssh-bf)")
	cmd.Flags().StringVarP(filter.IPEquals, "ip", "i", "", "restrict to alerts from this source ip (shorthand for --scope ip --value <IP>)")
	cmd.Flags().StringVarP(filter.RangeEquals, "range", "r", "", "restrict to alerts from this source range (shorthand for --scope range --value <RANGE>)")
	cmd.Flags().IntVarP(filter.Limit, "limit", "l", 100, "number of alerts to get (use 0 to remove the limit)")
	cmd.Flags().BoolVar(NoSimu, "no-simu", false, "exclude decisions in simulation mode")
	cmd.Flags().BoolVarP(&printMachine, "machine", "m", false, "print machines that triggered decisions")
	cmd.Flags().BoolVar(contained, "contained", false, "query decisions contained by range")

	return cmd
}

func (cli cliDecisions) NewAddCmd() *cobra.Command {
	var (
		addIP       string
		addRange    string
		addDuration string
		addValue    string
		addScope    string
		addReason   string
		addType     string
	)

	cmd := &cobra.Command{
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
		RunE: func(cmd *cobra.Command, args []string) error {
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
				return err
			}

			if addIP != "" {
				addValue = addIP
				addScope = types.Ip
			} else if addRange != "" {
				addValue = addRange
				addScope = types.Range
			} else if addValue == "" {
				printHelp(cmd)
				return fmt.Errorf("Missing arguments, a value is required (--ip, --range or --scope and --value)")
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
				return err
			}

			log.Info("Decision successfully added")
			return nil
		},
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().StringVarP(&addIP, "ip", "i", "", "Source ip (shorthand for --scope ip --value <IP>)")
	cmd.Flags().StringVarP(&addRange, "range", "r", "", "Range source ip (shorthand for --scope range --value <RANGE>)")
	cmd.Flags().StringVarP(&addDuration, "duration", "d", "4h", "Decision duration (ie. 1h,4h,30m)")
	cmd.Flags().StringVarP(&addValue, "value", "v", "", "The value (ie. --scope username --value foobar)")
	cmd.Flags().StringVar(&addScope, "scope", types.Ip, "Decision scope (ie. ip,range,username)")
	cmd.Flags().StringVarP(&addReason, "reason", "R", "", "Decision reason (ie. scenario-name)")
	cmd.Flags().StringVarP(&addType, "type", "t", "ban", "Decision type (ie. ban,captcha,throttle)")

	return cmd
}

func (cli cliDecisions) NewDeleteCmd() *cobra.Command {
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

	cmd := &cobra.Command{
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
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if delDecisionAll {
				return nil
			}
			if *delFilter.ScopeEquals == "" && *delFilter.ValueEquals == "" &&
				*delFilter.TypeEquals == "" && *delFilter.IPEquals == "" &&
				*delFilter.RangeEquals == "" && *delFilter.ScenarioEquals == "" &&
				*delFilter.OriginEquals == "" && delDecisionId == "" {
				cmd.Usage()
				return fmt.Errorf("at least one filter or --all must be specified")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			var decisions *models.DeleteDecisionResponse

			/*take care of shorthand options*/
			if err = manageCliDecisionAlerts(delFilter.IPEquals, delFilter.RangeEquals, delFilter.ScopeEquals, delFilter.ValueEquals); err != nil {
				return err
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
					return fmt.Errorf("Unable to delete decisions: %v", err)
				}
			} else {
				if _, err = strconv.Atoi(delDecisionId); err != nil {
					return fmt.Errorf("id '%s' is not an integer: %v", delDecisionId, err)
				}
				decisions, _, err = Client.Decisions.DeleteOne(context.Background(), delDecisionId)
				if err != nil {
					return fmt.Errorf("Unable to delete decision: %v", err)
				}
			}
			log.Infof("%s decision(s) deleted", decisions.NbDeleted)
			return nil
		},
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().StringVarP(delFilter.IPEquals, "ip", "i", "", "Source ip (shorthand for --scope ip --value <IP>)")
	cmd.Flags().StringVarP(delFilter.RangeEquals, "range", "r", "", "Range source ip (shorthand for --scope range --value <RANGE>)")
	cmd.Flags().StringVarP(delFilter.TypeEquals, "type", "t", "", "the decision type (ie. ban,captcha)")
	cmd.Flags().StringVarP(delFilter.ValueEquals, "value", "v", "", "the value to match for in the specified scope")
	cmd.Flags().StringVarP(delFilter.ScenarioEquals, "scenario", "s", "", "the scenario name (ie. crowdsecurity/ssh-bf)")
	cmd.Flags().StringVar(delFilter.OriginEquals, "origin", "", fmt.Sprintf("the value to match for the specified origin (%s ...)", strings.Join(types.GetOrigins(), ",")))

	cmd.Flags().StringVar(&delDecisionId, "id", "", "decision id")
	cmd.Flags().BoolVar(&delDecisionAll, "all", false, "delete all decisions")
	cmd.Flags().BoolVar(contained, "contained", false, "query decisions contained by range")

	return cmd
}
