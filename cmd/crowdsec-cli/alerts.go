package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/go-openapi/strfmt"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var printMachine bool
var limit *int

func DecisionsFromAlert(alert *models.Alert) string {
	ret := ""
	var decMap = make(map[string]int)
	for _, decision := range alert.Decisions {
		k := *decision.Type
		if *decision.Simulated {
			k = fmt.Sprintf("(simul)%s", k)
		}
		v := decMap[k]
		decMap[k] = v + 1
	}
	for k, v := range decMap {
		if len(ret) > 0 {
			ret += " "
		}
		ret += fmt.Sprintf("%s:%d", k, v)
	}
	return ret
}

func AlertsToTable(alerts *models.GetAlertsResponse, printMachine bool) error {

	if csConfig.Cscli.Output == "raw" {
		csvwriter := csv.NewWriter(os.Stdout)
		header := []string{"id", "scope", "value", "reason", "country", "as", "decisions", "created_at"}
		if printMachine {
			header = append(header, "machine")
		}
		err := csvwriter.Write(header)
		if err != nil {
			return err
		}
		for _, alertItem := range *alerts {
			row := []string{
				fmt.Sprintf("%d", alertItem.ID),
				*alertItem.Source.Scope,
				*alertItem.Source.Value,
				*alertItem.Scenario,
				alertItem.Source.Cn,
				alertItem.Source.AsNumber + " " + alertItem.Source.AsName,
				DecisionsFromAlert(alertItem),
				*alertItem.StartAt,
			}
			if printMachine {
				row = append(row, alertItem.MachineID)
			}
			err := csvwriter.Write(row)
			if err != nil {
				return err
			}
		}
		csvwriter.Flush()
	} else if csConfig.Cscli.Output == "json" {
		x, _ := json.MarshalIndent(alerts, "", " ")
		fmt.Printf("%s", string(x))
	} else if csConfig.Cscli.Output == "human" {

		table := tablewriter.NewWriter(os.Stdout)
		header := []string{"ID", "value", "reason", "country", "as", "decisions", "created_at"}
		if printMachine {
			header = append(header, "machine")
		}
		table.SetHeader(header)

		if len(*alerts) == 0 {
			fmt.Println("No active alerts")
			return nil
		}
		for _, alertItem := range *alerts {

			displayVal := *alertItem.Source.Scope
			if *alertItem.Source.Value != "" {
				displayVal += ":" + *alertItem.Source.Value
			}
			row := []string{
				strconv.Itoa(int(alertItem.ID)),
				displayVal,
				*alertItem.Scenario,
				alertItem.Source.Cn,
				alertItem.Source.AsNumber + " " + alertItem.Source.AsName,
				DecisionsFromAlert(alertItem),
				*alertItem.StartAt,
			}
			if printMachine {
				row = append(row, alertItem.MachineID)
			}
			table.Append(row)
		}
		table.Render() // Send output
	}
	return nil
}

func DisplayOneAlert(alert *models.Alert, withDetail bool) error {
	if csConfig.Cscli.Output == "human" {
		fmt.Printf("\n################################################################################################\n\n")
		scopeAndValue := *alert.Source.Scope
		if *alert.Source.Value != "" {
			scopeAndValue += ":" + *alert.Source.Value
		}
		fmt.Printf(" - ID         : %d\n", alert.ID)
		fmt.Printf(" - Date       : %s\n", alert.CreatedAt)
		fmt.Printf(" - Machine    : %s\n", alert.MachineID)
		fmt.Printf(" - Simulation : %v\n", *alert.Simulated)
		fmt.Printf(" - Reason     : %s\n", *alert.Scenario)
		fmt.Printf(" - Events Count : %d\n", *alert.EventsCount)
		fmt.Printf(" - Scope:Value: %s\n", scopeAndValue)
		fmt.Printf(" - Country    : %s\n", alert.Source.Cn)
		fmt.Printf(" - AS         : %s\n", alert.Source.AsName)
		fmt.Printf(" - Begin      : %s\n", *alert.StartAt)
		fmt.Printf(" - End        : %s\n\n", *alert.StopAt)
		foundActive := false
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"ID", "scope:value", "action", "expiration", "created_at"})
		for _, decision := range alert.Decisions {
			parsedDuration, err := time.ParseDuration(*decision.Duration)
			if err != nil {
				log.Errorf(err.Error())
			}
			expire := time.Now().UTC().Add(parsedDuration)
			if time.Now().UTC().After(expire) {
				continue
			}
			foundActive = true
			scopeAndValue := *decision.Scope
			if *decision.Value != "" {
				scopeAndValue += ":" + *decision.Value
			}
			table.Append([]string{
				strconv.Itoa(int(decision.ID)),
				scopeAndValue,
				*decision.Type,
				*decision.Duration,
				alert.CreatedAt,
			})
		}
		if foundActive {
			fmt.Printf(" - Active Decisions  :\n")
			table.Render() // Send output
		}

		if withDetail {
			fmt.Printf("\n - Events  :\n")
			for _, event := range alert.Events {
				fmt.Printf("\n- Date: %s\n", *event.Timestamp)
				table = tablewriter.NewWriter(os.Stdout)
				table.SetHeader([]string{"Key", "Value"})
				sort.Slice(event.Meta, func(i, j int) bool {
					return event.Meta[i].Key < event.Meta[j].Key
				})
				for _, meta := range event.Meta {
					table.Append([]string{
						meta.Key,
						meta.Value,
					})
				}

				table.Render() // Send output
			}
		}
	}
	return nil
}

func NewAlertsCmd() *cobra.Command {
	/* ---- ALERTS COMMAND */
	var cmdAlerts = &cobra.Command{
		Use:               "alerts [action]",
		Short:             "Manage alerts",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if err := csConfig.LoadAPIClient(); err != nil {
				return errors.Wrap(err, "loading api client")
			}
			apiURL, err := url.Parse(csConfig.API.Client.Credentials.URL)
			if err != nil {
				return errors.Wrapf(err, "parsing api url %s", apiURL)
			}
			Client, err = apiclient.NewClient(&apiclient.Config{
				MachineID:     csConfig.API.Client.Credentials.Login,
				Password:      strfmt.Password(csConfig.API.Client.Credentials.Password),
				UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
				URL:           apiURL,
				VersionPrefix: "v1",
			})

			if err != nil {
				return errors.Wrap(err, "new api client")
			}
			return nil
		},
	}

	var alertListFilter = apiclient.AlertsListOpts{
		ScopeEquals:    new(string),
		ValueEquals:    new(string),
		ScenarioEquals: new(string),
		IPEquals:       new(string),
		RangeEquals:    new(string),
		Since:          new(string),
		Until:          new(string),
		TypeEquals:     new(string),
	}
	limit = new(int)
	contained := new(bool)
	var cmdAlertsList = &cobra.Command{
		Use:   "list [filters]",
		Short: "List alerts",
		Example: `cscli alerts list
cscli alerts list --ip 1.2.3.4
cscli alerts list --range 1.2.3.0/24
cscli alerts list -s crowdsecurity/ssh-bf
cscli alerts list --type ban`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			var err error

			if err := manageCliDecisionAlerts(alertListFilter.IPEquals, alertListFilter.RangeEquals,
				alertListFilter.ScopeEquals, alertListFilter.ValueEquals); err != nil {
				printHelp(cmd)
				log.Fatalf("%s", err)
			}
			if limit != nil {
				alertListFilter.Limit = limit
			}

			if *alertListFilter.Until == "" {
				alertListFilter.Until = nil
			} else {
				/*time.ParseDuration support hours 'h' as bigger unit, let's make the user's life easier*/
				if strings.HasSuffix(*alertListFilter.Until, "d") {
					realDuration := strings.TrimSuffix(*alertListFilter.Until, "d")
					days, err := strconv.Atoi(realDuration)
					if err != nil {
						printHelp(cmd)
						log.Fatalf("Can't parse duration %s, valid durations format: 1d, 4h, 4h15m", *alertListFilter.Until)
					}
					*alertListFilter.Until = fmt.Sprintf("%d%s", days*24, "h")
				}
			}
			if *alertListFilter.Since == "" {
				alertListFilter.Since = nil
			} else {
				/*time.ParseDuration support hours 'h' as bigger unit, let's make the user's life easier*/
				if strings.HasSuffix(*alertListFilter.Since, "d") {
					realDuration := strings.TrimSuffix(*alertListFilter.Since, "d")
					days, err := strconv.Atoi(realDuration)
					if err != nil {
						printHelp(cmd)
						log.Fatalf("Can't parse duration %s, valid durations format: 1d, 4h, 4h15m", *alertListFilter.Since)
					}
					*alertListFilter.Since = fmt.Sprintf("%d%s", days*24, "h")
				}
			}
			if *alertListFilter.TypeEquals == "" {
				alertListFilter.TypeEquals = nil
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
			if contained != nil && *contained {
				alertListFilter.Contains = new(bool)
			}
			alerts, _, err := Client.Alerts.List(context.Background(), alertListFilter)
			if err != nil {
				log.Fatalf("Unable to list alerts : %v", err.Error())
			}

			err = AlertsToTable(alerts, printMachine)
			if err != nil {
				log.Fatalf("unable to list alerts : %v", err.Error())
			}
		},
	}
	cmdAlertsList.Flags().SortFlags = false
	cmdAlertsList.Flags().StringVar(alertListFilter.Until, "until", "", "restrict to alerts older than until (ie. 4h, 30d)")
	cmdAlertsList.Flags().StringVar(alertListFilter.Since, "since", "", "restrict to alerts newer than since (ie. 4h, 30d)")
	cmdAlertsList.Flags().StringVarP(alertListFilter.IPEquals, "ip", "i", "", "restrict to alerts from this source ip (shorthand for --scope ip --value <IP>)")
	cmdAlertsList.Flags().StringVarP(alertListFilter.ScenarioEquals, "scenario", "s", "", "the scenario (ie. crowdsecurity/ssh-bf)")
	cmdAlertsList.Flags().StringVarP(alertListFilter.RangeEquals, "range", "r", "", "restrict to alerts from this range (shorthand for --scope range --value <RANGE/X>)")
	cmdAlertsList.Flags().StringVar(alertListFilter.TypeEquals, "type", "", "restrict to alerts with given decision type (ie. ban, captcha)")
	cmdAlertsList.Flags().StringVar(alertListFilter.ScopeEquals, "scope", "", "restrict to alerts of this scope (ie. ip,range)")
	cmdAlertsList.Flags().StringVarP(alertListFilter.ValueEquals, "value", "v", "", "the value to match for in the specified scope")
	cmdAlertsList.Flags().BoolVar(contained, "contained", false, "query decisions contained by range")
	cmdAlertsList.Flags().BoolVarP(&printMachine, "machine", "m", false, "print machines that sent alerts")
	cmdAlertsList.Flags().IntVarP(limit, "limit", "l", 50, "limit size of alerts list table (0 to view all alerts)")
	cmdAlerts.AddCommand(cmdAlertsList)

	var ActiveDecision *bool
	var AlertDeleteAll bool
	var alertDeleteFilter = apiclient.AlertsDeleteOpts{
		ScopeEquals:    new(string),
		ValueEquals:    new(string),
		ScenarioEquals: new(string),
		IPEquals:       new(string),
		RangeEquals:    new(string),
	}
	var cmdAlertsDelete = &cobra.Command{
		Use: "delete [filters] [--all]",
		Short: `Delete alerts
/!\ This command can be use only on the same machine than the local API.`,
		Example: `cscli alerts delete --ip 1.2.3.4
cscli alerts delete --range 1.2.3.0/24
cscli alerts delete -s crowdsecurity/ssh-bf"`,
		DisableAutoGenTag: true,
		Aliases:           []string{"remove"},
		Args:              cobra.ExactArgs(0),
		PreRun: func(cmd *cobra.Command, args []string) {
			if AlertDeleteAll {
				return
			}
			if *alertDeleteFilter.ScopeEquals == "" && *alertDeleteFilter.ValueEquals == "" &&
				*alertDeleteFilter.ScenarioEquals == "" && *alertDeleteFilter.IPEquals == "" &&
				*alertDeleteFilter.RangeEquals == "" {
				_ = cmd.Usage()
				log.Fatalln("At least one filter or --all must be specified")
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			var err error

			if !AlertDeleteAll {
				if err := manageCliDecisionAlerts(alertDeleteFilter.IPEquals, alertDeleteFilter.RangeEquals,
					alertDeleteFilter.ScopeEquals, alertDeleteFilter.ValueEquals); err != nil {
					printHelp(cmd)
					log.Fatalf("%s", err)
				}
				if ActiveDecision != nil {
					alertDeleteFilter.ActiveDecisionEquals = ActiveDecision
				}

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
				if contained != nil && *contained {
					alertDeleteFilter.Contains = new(bool)
				}
			} else {
				limit := 0
				alertDeleteFilter = apiclient.AlertsDeleteOpts{Limit: &limit}
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
	cmdAlertsDelete.Flags().BoolVarP(&AlertDeleteAll, "all", "a", false, "delete all alerts")
	cmdAlertsDelete.Flags().BoolVar(contained, "contained", false, "query decisions contained by range")

	cmdAlerts.AddCommand(cmdAlertsDelete)

	var details bool
	var cmdAlertsInspect = &cobra.Command{
		Use:               `inspect "alert_id"`,
		Short:             `Show info about an alert`,
		Example:           `cscli alerts inspect 123`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				printHelp(cmd)
				return
			}
			for _, alertID := range args {
				id, err := strconv.Atoi(alertID)
				if err != nil {
					log.Fatalf("bad alert id %s", alertID)
					continue
				}
				alert, _, err := Client.Alerts.GetByID(context.Background(), id)
				if err != nil {
					log.Fatalf("can't find alert with id %s: %s", alertID, err)
				}
				switch csConfig.Cscli.Output {
				case "human":
					if err := DisplayOneAlert(alert, details); err != nil {
						continue
					}
				case "json":
					data, err := json.MarshalIndent(alert, "", "  ")
					if err != nil {
						log.Fatalf("unable to marshal alert with id %s: %s", alertID, err)
					}
					fmt.Printf("%s\n", string(data))
				case "raw":
					data, err := yaml.Marshal(alert)
					if err != nil {
						log.Fatalf("unable to marshal alert with id %s: %s", alertID, err)
					}
					fmt.Printf("%s\n", string(data))
				}
			}
		},
	}
	cmdAlertsInspect.Flags().SortFlags = false
	cmdAlertsInspect.Flags().BoolVarP(&details, "details", "d", false, "show alerts with events")

	cmdAlerts.AddCommand(cmdAlertsInspect)

	var maxItems int
	var maxAge string
	var cmdAlertsFlush = &cobra.Command{
		Use: `flush`,
		Short: `Flush alerts
/!\ This command can be used only on the same machine than the local API`,
		Example:           `cscli alerts flush --max-items 1000 --max-age 7d`,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if err := csConfig.LoadAPIServer(); err != nil || csConfig.DisableAPI {
				log.Fatal("Local API is disabled, please run this command on the local API machine")
			}
			if err := csConfig.LoadDBConfig(); err != nil {
				log.Fatalf(err.Error())
			}
			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Fatalf("unable to create new database client: %s", err)
			}
			log.Info("Flushing alerts. !! This may take a long time !!")
			err = dbClient.FlushAlerts(maxAge, maxItems)
			if err != nil {
				log.Fatalf("unable to flush alerts: %s", err)
			}
			log.Info("Alerts flushed")
		},
	}

	cmdAlertsFlush.Flags().SortFlags = false
	cmdAlertsFlush.Flags().IntVar(&maxItems, "max-items", 5000, "Maximum number of alert items to keep in the database")
	cmdAlertsFlush.Flags().StringVar(&maxAge, "max-age", "7d", "Maximum age of alert items to keep in the database")

	cmdAlerts.AddCommand(cmdAlertsFlush)

	return cmdAlerts
}
