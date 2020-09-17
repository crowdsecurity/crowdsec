package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/go-openapi/strfmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/goombaio/namegenerator"
	_ "github.com/mattn/go-sqlite3"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
)

var (
	IPAddressTemplate = []string{
		"192.168.0.%d",
		"10.10.0.%d",
		"172.16.0.%d",
		"172.16.40.%d",
		"192.168.30.%d",
		"10.10.10.%d",
	}
	scenarioTemplate = []string{
		"bf-ssh",
		"crawl-non-statics",
		"http-backdoors-attempts",
		"http-bad-user-agent",
		"http-bf-wordpress_bf",
	}
	AS = []string{
		"Orange S.A",
		"Level 3 Parent, LLC",
		"Zayo Bandwith",
		"Hurricane Electric LL",
		"NTT America, Inc",
		"Telia Company AB",
	}
	Countries = []string{
		"FR",
		"US",
		"EN",
		"IT",
		"CH",
		"RU",
	}

	machineIPAddrTemplate = "1.1.1.%d"
	MachineIDTemplate     = "machine%d"
	MachinePassword       = "%s"
)

type Machine struct {
	IPAddress string
	ID        string
	password  string
}

type Metrics struct {
	MachineID string
	NBSend    int
	Time      time.Duration
	nbElem    int
}

func (m *Machine) Run(apiURL string, nbQuery int, wg *sync.WaitGroup, metrics chan Metrics, filter apiclient.AlertsListOpts) {
	var Client *apiclient.ApiClient

	defer wg.Done()

	seed := time.Now().UTC().UnixNano()
	nameGenerator := namegenerator.NewNameGenerator(seed)
	name := nameGenerator.Generate()
	log.Printf("[Process:%s] Running", name)
	password := strfmt.Password(m.password)

	ctx := context.Background()

	Client = apiclient.NewClient(nil)
	_, err := Client.Auth.RegisterWatcher(ctx, models.WatcherRegistrationRequest{MachineID: &m.ID, Password: &password})
	if err != nil {
		// machine is already register ?
		//log.Errorf("err : %+v \n", err.Error())
	}

	apiclient.BaseURL, _ = url.Parse(apiURL)

	t := &apiclient.JWTTransport{
		MachineID: &m.ID,
		Password:  &password,
		Scenarios: []string{"aaaaaa", "bbbbb"},
	}
	Client = apiclient.NewClient(t.Client())

	now := time.Now()
	alerts, _, err := Client.Alerts.List(context.Background(), filter)
	if err != nil {
		log.Fatalf(err.Error())
	}

	metrics <- Metrics{MachineID: m.ID, NBSend: nbQuery, Time: time.Now().Sub(now), nbElem: len(*alerts)}
}

func main() {
	var wg sync.WaitGroup

	nbMachine := flag.Int("c", 10, "Number of concurrent simulated machines")
	nbQuery := flag.Int("n", 1, "Nb query per machine")
	//random := flag.Bool("r", false, "Generate random filter")
	sourceScope := flag.String("scope", "", "Scope of the alerts")
	sourceValue := flag.String("value", "", "value of the requests alerts")
	scenario := flag.String("scenario", "", "scenario of the alert")
	ip := flag.String("ip", "", "ip to query")
	IPRange := flag.String("range", "", "range to query")
	since := flag.String("since", "", "alerts added after <date>")
	until := flag.String("until", "", "search alert before <date>")
	activeDecision := flag.Bool("active", false, "only return alerts with active decisions")
	source := flag.String("source", "", "source of the alerts (cscli, crowdsec, api ...)")

	url := flag.String("u", "http://localhost:8080/", "URL of API")
	flag.Parse()

	cleanURL := *url

	if !strings.HasSuffix(cleanURL, "/") {
		cleanURL = fmt.Sprintf("%s/", cleanURL)
	}

	metricsChan := make(chan Metrics, *nbMachine)

	filter := apiclient.AlertsListOpts{}

	if *sourceScope != "" {
		filter.ScopeEquals = sourceScope
	}
	if *sourceValue != "" {
		filter.ValueEquals = sourceValue
	}
	if *scenario != "" {
		filter.ScenarioEquals = scenario
	}
	if *ip != "" {
		filter.IPEquals = ip
	}
	if *IPRange != "" {
		filter.RangeEquals = IPRange
	}
	if *since != "" {
		filter.SinceEquals = since
	}
	if *until != "" {
		filter.UntilEquals = until
	}
	if *activeDecision {
		filter.ActiveDecisionEquals = activeDecision
	}
	if *source != "" {
		filter.SourceEquals = source
	}
	log.Printf("Query alert with filter: %+v", filter)

	for i := 0; i <= *nbMachine-1; i++ {
		machine := &Machine{
			IPAddress: fmt.Sprintf(machineIPAddrTemplate, rand.Intn(254)),
			ID:        fmt.Sprintf(MachineIDTemplate, i),
			password:  "abcdefgh",
		}
		wg.Add(1)
		go machine.Run(*url, *nbQuery, &wg, metricsChan, filter)
	}

	wg.Wait()

	log.Printf("All go routines finished")
	close(metricsChan)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")

	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	table.SetHeader([]string{"Machine", "Nb elements", "Time to send"})

	for m := range metricsChan {
		table.Append([]string{m.MachineID, fmt.Sprintf("%d", m.nbElem), fmt.Sprintf("%s", m.Time)})
	}

	table.Render()

}
