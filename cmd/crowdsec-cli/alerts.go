package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/fatih/color"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/maptools"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func DecisionsFromAlert(alert *models.Alert) string {
	ret := ""
	decMap := make(map[string]int)

	for _, decision := range alert.Decisions {
		k := *decision.Type
		if *decision.Simulated {
			k = fmt.Sprintf("(simul)%s", k)
		}

		v := decMap[k]
		decMap[k] = v + 1
	}

	for _, key := range maptools.SortedKeys(decMap) {
		if len(ret) > 0 {
			ret += " "
		}

		ret += fmt.Sprintf("%s:%d", key, decMap[key])
	}

	return ret
}

func (cli *cliAlerts) alertsToTable(alerts *models.GetAlertsResponse, printMachine bool) error {
	switch cli.cfg().Cscli.Output {
	case "raw":
		csvwriter := csv.NewWriter(os.Stdout)
		header := []string{"id", "scope", "value", "reason", "country", "as", "decisions", "created_at"}

		if printMachine {
			header = append(header, "machine")
		}

		if err := csvwriter.Write(header); err != nil {
			return err
		}

		for _, alertItem := range *alerts {
			row := []string{
				strconv.FormatInt(alertItem.ID, 10),
				*alertItem.Source.Scope,
				*alertItem.Source.Value,
				*alertItem.Scenario,
				alertItem.Source.Cn,
				alertItem.Source.GetAsNumberName(),
				DecisionsFromAlert(alertItem),
				*alertItem.StartAt,
			}
			if printMachine {
				row = append(row, alertItem.MachineID)
			}

			if err := csvwriter.Write(row); err != nil {
				return err
			}
		}

		csvwriter.Flush()
	case "json":
		if *alerts == nil {
			// avoid returning "null" in json
			// could be cleaner if we used slice of alerts directly
			fmt.Println("[]")
			return nil
		}

		x, _ := json.MarshalIndent(alerts, "", " ")
		fmt.Print(string(x))
	case "human":
		if len(*alerts) == 0 {
			fmt.Println("No active alerts")
			return nil
		}

		alertsTable(color.Output, alerts, printMachine)
	}

	return nil
}

func (cli *cliAlerts) displayOneAlert(alert *models.Alert, withDetail bool) error {
	alertTemplate := `
################################################################################################

 - ID           : {{.ID}}
 - Date         : {{.CreatedAt}}
 - Machine      : {{.MachineID}}
 - Simulation   : {{.Simulated}}
 - Reason       : {{.Scenario}}
 - Events Count : {{.EventsCount}}
 - Scope:Value  : {{.Source.Scope}}{{if .Source.Value}}:{{.Source.Value}}{{end}}
 - Country      : {{.Source.Cn}}
 - AS           : {{.Source.AsName}}
 - Begin        : {{.StartAt}}
 - End          : {{.StopAt}}
 - UUID         : {{.UUID}}

`

	tmpl, err := template.New("alert").Parse(alertTemplate)
	if err != nil {
		return err
	}

	if err = tmpl.Execute(os.Stdout, alert); err != nil {
		return err
	}

	alertDecisionsTable(color.Output, alert)

	if len(alert.Meta) > 0 {
		fmt.Printf("\n - Context  :\n")
		sort.Slice(alert.Meta, func(i, j int) bool {
			return alert.Meta[i].Key < alert.Meta[j].Key
		})

		table := newTable(color.Output)
		table.SetRowLines(false)
		table.SetHeaders("Key", "Value")

		for _, meta := range alert.Meta {
			var valSlice []string
			if err := json.Unmarshal([]byte(meta.Value), &valSlice); err != nil {
				return fmt.Errorf("unknown context value type '%s': %w", meta.Value, err)
			}

			for _, value := range valSlice {
				table.AddRow(
					meta.Key,
					value,
				)
			}
		}

		table.Render()
	}

	if withDetail {
		fmt.Printf("\n - Events  :\n")

		for _, event := range alert.Events {
			alertEventTable(color.Output, event)
		}
	}

	return nil
}

type cliAlerts struct {
	client *apiclient.ApiClient
	cfg    configGetter
}

func NewCLIAlerts(getconfig configGetter) *cliAlerts {
	return &cliAlerts{
		cfg: getconfig,
	}
}

func (cli *cliAlerts) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "alerts [action]",
		Short:             "Manage alerts",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		Aliases:           []string{"alert"},
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			cfg := cli.cfg()
			if err := cfg.LoadAPIClient(); err != nil {
				return fmt.Errorf("loading api client: %w", err)
			}
			apiURL, err := url.Parse(cfg.API.Client.Credentials.URL)
			if err != nil {
				return fmt.Errorf("parsing api url %s: %w", apiURL, err)
			}

			cli.client, err = apiclient.NewClient(&apiclient.Config{
				MachineID:     cfg.API.Client.Credentials.Login,
				Password:      strfmt.Password(cfg.API.Client.Credentials.Password),
				UserAgent:     cwversion.UserAgent(),
				URL:           apiURL,
				VersionPrefix: "v1",
			})
			if err != nil {
				return fmt.Errorf("new api client: %w", err)
			}

			return nil
		},
	}

	cmd.AddCommand(cli.NewListCmd())
	cmd.AddCommand(cli.NewInspectCmd())
	cmd.AddCommand(cli.NewFlushCmd())
	cmd.AddCommand(cli.NewDeleteCmd())

	return cmd
}

func (cli *cliAlerts) list(alertListFilter apiclient.AlertsListOpts, limit *int, contained *bool, printMachine bool) error {
	if err := manageCliDecisionAlerts(alertListFilter.IPEquals, alertListFilter.RangeEquals,
		alertListFilter.ScopeEquals, alertListFilter.ValueEquals); err != nil {
		return err
	}

	if limit != nil {
		alertListFilter.Limit = limit
	}

	if *alertListFilter.Until == "" {
		alertListFilter.Until = nil
	} else if strings.HasSuffix(*alertListFilter.Until, "d") {
		/*time.ParseDuration support hours 'h' as bigger unit, let's make the user's life easier*/
		realDuration := strings.TrimSuffix(*alertListFilter.Until, "d")

		days, err := strconv.Atoi(realDuration)
		if err != nil {
			return fmt.Errorf("can't parse duration %s, valid durations format: 1d, 4h, 4h15m", *alertListFilter.Until)
		}

		*alertListFilter.Until = fmt.Sprintf("%d%s", days*24, "h")
	}

	if *alertListFilter.Since == "" {
		alertListFilter.Since = nil
	} else if strings.HasSuffix(*alertListFilter.Since, "d") {
		// time.ParseDuration support hours 'h' as bigger unit, let's make the user's life easier
		realDuration := strings.TrimSuffix(*alertListFilter.Since, "d")

		days, err := strconv.Atoi(realDuration)
		if err != nil {
			return fmt.Errorf("can't parse duration %s, valid durations format: 1d, 4h, 4h15m", *alertListFilter.Since)
		}

		*alertListFilter.Since = fmt.Sprintf("%d%s", days*24, "h")
	}

	if *alertListFilter.IncludeCAPI {
		*alertListFilter.Limit = 0
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

	if *alertListFilter.OriginEquals == "" {
		alertListFilter.OriginEquals = nil
	}

	if contained != nil && *contained {
		alertListFilter.Contains = new(bool)
	}

	alerts, _, err := cli.client.Alerts.List(context.Background(), alertListFilter)
	if err != nil {
		return fmt.Errorf("unable to list alerts: %w", err)
	}

	if err = cli.alertsToTable(alerts, printMachine); err != nil {
		return fmt.Errorf("unable to list alerts: %w", err)
	}

	return nil
}

func (cli *cliAlerts) NewListCmd() *cobra.Command {
	alertListFilter := apiclient.AlertsListOpts{
		ScopeEquals:    new(string),
		ValueEquals:    new(string),
		ScenarioEquals: new(string),
		IPEquals:       new(string),
		RangeEquals:    new(string),
		Since:          new(string),
		Until:          new(string),
		TypeEquals:     new(string),
		IncludeCAPI:    new(bool),
		OriginEquals:   new(string),
	}

	limit := new(int)
	contained := new(bool)

	var printMachine bool

	cmd := &cobra.Command{
		Use:   "list [filters]",
		Short: "List alerts",
		Example: `cscli alerts list
cscli alerts list --ip 1.2.3.4
cscli alerts list --range 1.2.3.0/24
cscli alerts list --origin lists
cscli alerts list -s crowdsecurity/ssh-bf
cscli alerts list --type ban`,
		Long:              `List alerts with optional filters`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.list(alertListFilter, limit, contained, printMachine)
		},
	}

	flags := cmd.Flags()
	flags.SortFlags = false
	flags.BoolVarP(alertListFilter.IncludeCAPI, "all", "a", false, "Include decisions from Central API")
	flags.StringVar(alertListFilter.Until, "until", "", "restrict to alerts older than until (ie. 4h, 30d)")
	flags.StringVar(alertListFilter.Since, "since", "", "restrict to alerts newer than since (ie. 4h, 30d)")
	flags.StringVarP(alertListFilter.IPEquals, "ip", "i", "", "restrict to alerts from this source ip (shorthand for --scope ip --value <IP>)")
	flags.StringVarP(alertListFilter.ScenarioEquals, "scenario", "s", "", "the scenario (ie. crowdsecurity/ssh-bf)")
	flags.StringVarP(alertListFilter.RangeEquals, "range", "r", "", "restrict to alerts from this range (shorthand for --scope range --value <RANGE/X>)")
	flags.StringVar(alertListFilter.TypeEquals, "type", "", "restrict to alerts with given decision type (ie. ban, captcha)")
	flags.StringVar(alertListFilter.ScopeEquals, "scope", "", "restrict to alerts of this scope (ie. ip,range)")
	flags.StringVarP(alertListFilter.ValueEquals, "value", "v", "", "the value to match for in the specified scope")
	flags.StringVar(alertListFilter.OriginEquals, "origin", "", fmt.Sprintf("the value to match for the specified origin (%s ...)", strings.Join(types.GetOrigins(), ",")))
	flags.BoolVar(contained, "contained", false, "query decisions contained by range")
	flags.BoolVarP(&printMachine, "machine", "m", false, "print machines that sent alerts")
	flags.IntVarP(limit, "limit", "l", 50, "limit size of alerts list table (0 to view all alerts)")

	return cmd
}

func (cli *cliAlerts) NewDeleteCmd() *cobra.Command {
	var (
		ActiveDecision *bool
		AlertDeleteAll bool
		delAlertByID   string
	)

	alertDeleteFilter := apiclient.AlertsDeleteOpts{
		ScopeEquals:    new(string),
		ValueEquals:    new(string),
		ScenarioEquals: new(string),
		IPEquals:       new(string),
		RangeEquals:    new(string),
	}

	contained := new(bool)

	cmd := &cobra.Command{
		Use: "delete [filters] [--all]",
		Short: `Delete alerts
/!\ This command can be use only on the same machine than the local API.`,
		Example: `cscli alerts delete --ip 1.2.3.4
cscli alerts delete --range 1.2.3.0/24
cscli alerts delete -s crowdsecurity/ssh-bf"`,
		DisableAutoGenTag: true,
		Aliases:           []string{"remove"},
		Args:              cobra.ExactArgs(0),
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			if AlertDeleteAll {
				return nil
			}
			if *alertDeleteFilter.ScopeEquals == "" && *alertDeleteFilter.ValueEquals == "" &&
				*alertDeleteFilter.ScenarioEquals == "" && *alertDeleteFilter.IPEquals == "" &&
				*alertDeleteFilter.RangeEquals == "" && delAlertByID == "" {
				_ = cmd.Usage()
				return errors.New("at least one filter or --all must be specified")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			var err error

			if !AlertDeleteAll {
				if err = manageCliDecisionAlerts(alertDeleteFilter.IPEquals, alertDeleteFilter.RangeEquals,
					alertDeleteFilter.ScopeEquals, alertDeleteFilter.ValueEquals); err != nil {
					printHelp(cmd)
					return err
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
				limit := 0
				alertDeleteFilter.Limit = &limit
			} else {
				limit := 0
				alertDeleteFilter = apiclient.AlertsDeleteOpts{Limit: &limit}
			}

			var alerts *models.DeleteAlertsResponse
			if delAlertByID == "" {
				alerts, _, err = cli.client.Alerts.Delete(context.Background(), alertDeleteFilter)
				if err != nil {
					return fmt.Errorf("unable to delete alerts: %w", err)
				}
			} else {
				alerts, _, err = cli.client.Alerts.DeleteOne(context.Background(), delAlertByID)
				if err != nil {
					return fmt.Errorf("unable to delete alert: %w", err)
				}
			}
			log.Infof("%s alert(s) deleted", alerts.NbDeleted)

			return nil
		},
	}

	flags := cmd.Flags()
	flags.SortFlags = false
	flags.StringVar(alertDeleteFilter.ScopeEquals, "scope", "", "the scope (ie. ip,range)")
	flags.StringVarP(alertDeleteFilter.ValueEquals, "value", "v", "", "the value to match for in the specified scope")
	flags.StringVarP(alertDeleteFilter.ScenarioEquals, "scenario", "s", "", "the scenario (ie. crowdsecurity/ssh-bf)")
	flags.StringVarP(alertDeleteFilter.IPEquals, "ip", "i", "", "Source ip (shorthand for --scope ip --value <IP>)")
	flags.StringVarP(alertDeleteFilter.RangeEquals, "range", "r", "", "Range source ip (shorthand for --scope range --value <RANGE>)")
	flags.StringVar(&delAlertByID, "id", "", "alert ID")
	flags.BoolVarP(&AlertDeleteAll, "all", "a", false, "delete all alerts")
	flags.BoolVar(contained, "contained", false, "query decisions contained by range")

	return cmd
}

func (cli *cliAlerts) inspect(details bool, alertIDs ...string) error {
	cfg := cli.cfg()

	for _, alertID := range alertIDs {
		id, err := strconv.Atoi(alertID)
		if err != nil {
			return fmt.Errorf("bad alert id %s", alertID)
		}

		alert, _, err := cli.client.Alerts.GetByID(context.Background(), id)
		if err != nil {
			return fmt.Errorf("can't find alert with id %s: %w", alertID, err)
		}

		switch cfg.Cscli.Output {
		case "human":
			if err := cli.displayOneAlert(alert, details); err != nil {
				log.Warnf("unable to display alert with id %s: %s", alertID, err)
				continue
			}
		case "json":
			data, err := json.MarshalIndent(alert, "", "  ")
			if err != nil {
				return fmt.Errorf("unable to marshal alert with id %s: %w", alertID, err)
			}

			fmt.Printf("%s\n", string(data))
		case "raw":
			data, err := yaml.Marshal(alert)
			if err != nil {
				return fmt.Errorf("unable to marshal alert with id %s: %w", alertID, err)
			}

			fmt.Println(string(data))
		}
	}

	return nil
}

func (cli *cliAlerts) NewInspectCmd() *cobra.Command {
	var details bool

	cmd := &cobra.Command{
		Use:               `inspect "alert_id"`,
		Short:             `Show info about an alert`,
		Example:           `cscli alerts inspect 123`,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				printHelp(cmd)
				return errors.New("missing alert_id")
			}
			return cli.inspect(details, args...)
		},
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().BoolVarP(&details, "details", "d", false, "show alerts with events")

	return cmd
}

func (cli *cliAlerts) NewFlushCmd() *cobra.Command {
	var (
		maxItems int
		maxAge   string
	)

	cmd := &cobra.Command{
		Use: `flush`,
		Short: `Flush alerts
/!\ This command can be used only on the same machine than the local API`,
		Example:           `cscli alerts flush --max-items 1000 --max-age 7d`,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg := cli.cfg()
			if err := require.LAPI(cfg); err != nil {
				return err
			}
			db, err := database.NewClient(cfg.DbConfig)
			if err != nil {
				return fmt.Errorf("unable to create new database client: %w", err)
			}
			log.Info("Flushing alerts. !! This may take a long time !!")
			err = db.FlushAlerts(maxAge, maxItems)
			if err != nil {
				return fmt.Errorf("unable to flush alerts: %w", err)
			}
			log.Info("Alerts flushed")

			return nil
		},
	}

	cmd.Flags().SortFlags = false
	cmd.Flags().IntVar(&maxItems, "max-items", 5000, "Maximum number of alert items to keep in the database")
	cmd.Flags().StringVar(&maxAge, "max-age", "7d", "Maximum age of alert items to keep in the database")

	return cmd
}
