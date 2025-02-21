package clidecision

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
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

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clialert"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type configGetter func() *csconfig.Config

type cliDecisions struct {
	client *apiclient.ApiClient
	cfg    configGetter
}

func (cli *cliDecisions) decisionsToTable(alerts *models.GetAlertsResponse, printMachine bool) error {
	/*here we cheat a bit : to make it more readable for the user, we dedup some entries*/
	spamLimit := make(map[string]bool)
	skipped := 0

	for aIdx := range len(*alerts) {
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

	switch cli.cfg().Cscli.Output {
	case "raw":
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
					strconv.FormatInt(decisionItem.ID, 10),
					*decisionItem.Origin,
					*decisionItem.Scope + ":" + *decisionItem.Value,
					*decisionItem.Scenario,
					*decisionItem.Type,
					alertItem.Source.Cn,
					alertItem.Source.GetAsNumberName(),
					strconv.FormatInt(int64(*alertItem.EventsCount), 10),
					*decisionItem.Duration,
					strconv.FormatBool(*decisionItem.Simulated),
					strconv.FormatInt(alertItem.ID, 10),
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
	case "json":
		if *alerts == nil {
			// avoid returning "null" in `json"
			// could be cleaner if we used slice of alerts directly
			fmt.Println("[]")
			return nil
		}

		x, _ := json.MarshalIndent(alerts, "", " ")
		fmt.Printf("%s", string(x))
	case "human":
		if len(*alerts) == 0 {
			fmt.Println("No active decisions")
			return nil
		}

		cli.decisionsTable(color.Output, alerts, printMachine)

		if skipped > 0 {
			fmt.Printf("%d duplicated entries skipped\n", skipped)
		}
	}

	return nil
}

func New(cfg configGetter) *cliDecisions {
	return &cliDecisions{
		cfg: cfg,
	}
}

func (cli *cliDecisions) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "decisions [action]",
		Short:   "Manage decisions",
		Long:    `Add/List/Delete/Import decisions from LAPI`,
		Example: `cscli decisions [action] [filter]`,
		Aliases: []string{"decision"},
		/*TBD example*/
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			cfg := cli.cfg()
			if err := cfg.LoadAPIClient(); err != nil {
				return fmt.Errorf("loading api client: %w", err)
			}
			apiURL, err := url.Parse(cfg.API.Client.Credentials.URL)
			if err != nil {
				return fmt.Errorf("parsing api url: %w", err)
			}

			cli.client, err = apiclient.NewClient(&apiclient.Config{
				MachineID:     cfg.API.Client.Credentials.Login,
				Password:      strfmt.Password(cfg.API.Client.Credentials.Password),
				URL:           apiURL,
				VersionPrefix: "v1",
			})
			if err != nil {
				return fmt.Errorf("creating api client: %w", err)
			}

			return nil
		},
	}

	cmd.AddCommand(cli.newListCmd())
	cmd.AddCommand(cli.newAddCmd())
	cmd.AddCommand(cli.newDeleteCmd())
	cmd.AddCommand(cli.newImportCmd())

	return cmd
}

func (cli *cliDecisions) list(ctx context.Context, filter apiclient.AlertsListOpts, noSimu *bool, contained *bool, printMachine bool) error {
	var err error

	*filter.ScopeEquals, err = clialert.SanitizeScope(*filter.ScopeEquals, *filter.IPEquals, *filter.RangeEquals)
	if err != nil {
		return err
	}

	filter.ActiveDecisionEquals = new(bool)
	*filter.ActiveDecisionEquals = true

	if noSimu != nil && *noSimu {
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

	alerts, _, err := cli.client.Alerts.List(ctx, filter)
	if err != nil {
		return fmt.Errorf("unable to retrieve decisions: %w", err)
	}

	err = cli.decisionsToTable(alerts, printMachine)
	if err != nil {
		return fmt.Errorf("unable to print decisions: %w", err)
	}

	return nil
}

func (cli *cliDecisions) newListCmd() *cobra.Command {
	filter := apiclient.AlertsListOpts{
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
cscli decisions list --origin lists --scenario list_name
`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.list(cmd.Context(), filter, NoSimu, contained, printMachine)
		},
	}

	flags := cmd.Flags()
	flags.SortFlags = false
	flags.BoolVarP(filter.IncludeCAPI, "all", "a", false, "Include decisions from Central API")
	flags.StringVar(filter.Since, "since", "", "restrict to alerts newer than since (ie. 4h, 30d)")
	flags.StringVar(filter.Until, "until", "", "restrict to alerts older than until (ie. 4h, 30d)")
	flags.StringVarP(filter.TypeEquals, "type", "t", "", "restrict to this decision type (ie. ban,captcha)")
	flags.StringVar(filter.ScopeEquals, "scope", "", "restrict to this scope (ie. ip,range,session)")
	flags.StringVar(filter.OriginEquals, "origin", "", fmt.Sprintf("the value to match for the specified origin (%s ...)", strings.Join(types.GetOrigins(), ",")))
	flags.StringVarP(filter.ValueEquals, "value", "v", "", "restrict to this value (ie. 1.2.3.4,userName)")
	flags.StringVarP(filter.ScenarioEquals, "scenario", "s", "", "restrict to this scenario (ie. crowdsecurity/ssh-bf)")
	flags.StringVarP(filter.IPEquals, "ip", "i", "", "restrict to alerts from this source ip (shorthand for --scope ip --value <IP>)")
	flags.StringVarP(filter.RangeEquals, "range", "r", "", "restrict to alerts from this source range (shorthand for --scope range --value <RANGE>)")
	flags.IntVarP(filter.Limit, "limit", "l", 100, "number of alerts to get (use 0 to remove the limit)")
	flags.BoolVar(NoSimu, "no-simu", false, "exclude decisions in simulation mode")
	flags.BoolVarP(&printMachine, "machine", "m", false, "print machines that triggered decisions")
	flags.BoolVar(contained, "contained", false, "query decisions contained by range")

	return cmd
}

//nolint:revive // we'll reduce the number of args later
func (cli *cliDecisions) add(ctx context.Context, addIP, addRange, addDuration, addValue, addScope, addReason, addType string, bypassAllowlist bool) error {
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

	var err error

	addScope, err = clialert.SanitizeScope(addScope, addIP, addRange)
	if err != nil {
		return err
	}

	if addIP != "" {
		addValue = addIP
		addScope = types.Ip
	} else if addRange != "" {
		addValue = addRange
		addScope = types.Range
	} else if addValue == "" {
		return errors.New("missing arguments, a value is required (--ip, --range or --scope and --value)")
	}

	if addReason == "" {
		addReason = fmt.Sprintf("manual '%s' from '%s'", addType, cli.cfg().API.Client.Credentials.Login)
	}

	if !bypassAllowlist && (addScope == types.Ip || addScope == types.Range) {
		resp, _, err := cli.client.Allowlists.CheckIfAllowlistedWithReason(ctx, addValue)
		if err != nil {
			log.Errorf("Cannot check if %s is in allowlist: %s", addValue, err)
		} else if resp.Allowlisted {
			return fmt.Errorf("%s is allowlisted by item %s, use --bypass-allowlist to add the decision anyway", addValue, resp.Reason)
		}
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
		// setting empty scope/value broke plugins, and it didn't seem to be needed anymore w/ latest papi changes
		Source: &models.Source{
			AsName:   "",
			AsNumber: "",
			Cn:       "",
			IP:       addValue,
			Range:    "",
			Scope:    &addScope,
			Value:    &addValue,
		},
		StartAt:     &startAt,
		StopAt:      &stopAt,
		CreatedAt:   createdAt,
		Remediation: true,
	}
	alerts = append(alerts, &alert)

	_, _, err = cli.client.Alerts.Add(ctx, alerts)
	if err != nil {
		return err
	}

	log.Info("Decision successfully added")

	return nil
}

func (cli *cliDecisions) newAddCmd() *cobra.Command {
	var (
		addIP           string
		addRange        string
		addDuration     string
		addValue        string
		addScope        string
		addReason       string
		addType         string
		bypassAllowlist bool
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
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.add(cmd.Context(), addIP, addRange, addDuration, addValue, addScope, addReason, addType, bypassAllowlist)
		},
	}

	flags := cmd.Flags()
	flags.SortFlags = false
	flags.StringVarP(&addIP, "ip", "i", "", "Source ip (shorthand for --scope ip --value <IP>)")
	flags.StringVarP(&addRange, "range", "r", "", "Range source ip (shorthand for --scope range --value <RANGE>)")
	flags.StringVarP(&addDuration, "duration", "d", "4h", "Decision duration (ie. 1h,4h,30m)")
	flags.StringVarP(&addValue, "value", "v", "", "The value (ie. --scope username --value foobar)")
	flags.StringVar(&addScope, "scope", types.Ip, "Decision scope (ie. ip,range,username)")
	flags.StringVarP(&addReason, "reason", "R", "", "Decision reason (ie. scenario-name)")
	flags.StringVarP(&addType, "type", "t", "ban", "Decision type (ie. ban,captcha,throttle)")
	flags.BoolVarP(&bypassAllowlist, "bypass-allowlist", "B", false, "Add decision even if value is in allowlist")

	return cmd
}

func (cli *cliDecisions) delete(ctx context.Context, delFilter apiclient.DecisionsDeleteOpts, delDecisionID string, contained *bool) error {
	var err error

	/*take care of shorthand options*/
	*delFilter.ScopeEquals, err = clialert.SanitizeScope(*delFilter.ScopeEquals, *delFilter.IPEquals, *delFilter.RangeEquals)
	if err != nil {
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

	var decisions *models.DeleteDecisionResponse

	if delDecisionID == "" {
		decisions, _, err = cli.client.Decisions.Delete(ctx, delFilter)
		if err != nil {
			return fmt.Errorf("unable to delete decisions: %w", err)
		}
	} else {
		if _, err = strconv.Atoi(delDecisionID); err != nil {
			return fmt.Errorf("id '%s' is not an integer: %w", delDecisionID, err)
		}

		decisions, _, err = cli.client.Decisions.DeleteOne(ctx, delDecisionID)
		if err != nil {
			return fmt.Errorf("unable to delete decision: %w", err)
		}
	}

	log.Infof("%s decision(s) deleted", decisions.NbDeleted)

	return nil
}

func (cli *cliDecisions) newDeleteCmd() *cobra.Command {
	delFilter := apiclient.DecisionsDeleteOpts{
		ScopeEquals:    new(string),
		ValueEquals:    new(string),
		TypeEquals:     new(string),
		IPEquals:       new(string),
		RangeEquals:    new(string),
		ScenarioEquals: new(string),
		OriginEquals:   new(string),
	}

	var delDecisionID string

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
cscli decisions delete --origin lists  --scenario list_name
`,
		/*TBD : refaire le Long/Example*/
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			if delDecisionAll {
				return nil
			}
			if *delFilter.ScopeEquals == "" && *delFilter.ValueEquals == "" &&
				*delFilter.TypeEquals == "" && *delFilter.IPEquals == "" &&
				*delFilter.RangeEquals == "" && *delFilter.ScenarioEquals == "" &&
				*delFilter.OriginEquals == "" && delDecisionID == "" {
				_ = cmd.Usage()
				return errors.New("at least one filter or --all must be specified")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.delete(cmd.Context(), delFilter, delDecisionID, contained)
		},
	}

	flags := cmd.Flags()
	flags.SortFlags = false
	flags.StringVarP(delFilter.IPEquals, "ip", "i", "", "Source ip (shorthand for --scope ip --value <IP>)")
	flags.StringVarP(delFilter.RangeEquals, "range", "r", "", "Range source ip (shorthand for --scope range --value <RANGE>)")
	flags.StringVarP(delFilter.TypeEquals, "type", "t", "", "the decision type (ie. ban,captcha)")
	flags.StringVarP(delFilter.ValueEquals, "value", "v", "", "the value to match for in the specified scope")
	flags.StringVarP(delFilter.ScenarioEquals, "scenario", "s", "", "the scenario name (ie. crowdsecurity/ssh-bf)")
	flags.StringVar(delFilter.OriginEquals, "origin", "", fmt.Sprintf("the value to match for the specified origin (%s ...)", strings.Join(types.GetOrigins(), ",")))

	flags.StringVar(&delDecisionID, "id", "", "decision id")
	flags.BoolVar(&delDecisionAll, "all", false, "delete all decisions")
	flags.BoolVar(contained, "contained", false, "query decisions contained by range")

	return cmd
}
