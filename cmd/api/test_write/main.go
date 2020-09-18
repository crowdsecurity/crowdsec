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

	"github.com/go-openapi/strfmt"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	_ "github.com/go-sql-driver/mysql"
	"github.com/goombaio/namegenerator"
	_ "github.com/mattn/go-sqlite3"
	"github.com/olekukonko/tablewriter"
	"github.com/rs/xid"
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
	ID        *string
	password  *strfmt.Password
}

type Metrics struct {
	MachineID string
	NBSend    int
	Time      time.Duration
	Bulk      bool // bulk or single
}

func (m *Machine) CreateAlert() *models.Alert {

	guid := xid.New()
	ip := IPAddressTemplate[rand.Intn(len(IPAddressTemplate))]
	ipAddr := fmt.Sprintf(ip, rand.Intn(254))
	ipRange := fmt.Sprintf(ip+"/24", 0)

	startIP, endIP, err := database.GetIpsFromIpRange(ipAddr + "/32")
	if err != nil {
		log.Fatalf("unable to have end and start ip for '%s'", ipAddr)
	}

	scenario := fmt.Sprintf("crowdsecurity/%s", scenarioTemplate[rand.Intn(len(scenarioTemplate))])
	duration := fmt.Sprintf("%dh", rand.Intn(4))
	origin := "crowdsec"
	scope := "ip"
	decisionType := "ban"
	decision := &models.Decision{
		ID:       guid.String(),
		Duration: &duration,
		EndIP:    endIP,
		StartIP:  startIP,
		Origin:   &origin,
		Scenario: &scenario,
		Scope:    &scope,
		Target:   &ipAddr,
		Type:     &decisionType,
	}

	events := []*models.Event{}
	timestamp := time.Now().Format(time.RFC3339)
	event := &models.Event{
		Meta:      models.Meta{},
		Timestamp: &timestamp,
	}
	MetaItem := &models.MetaItems0{
		Key:   "ip",
		Value: ipAddr,
	}
	event.Meta = append(event.Meta, MetaItem)
	MetaItem = &models.MetaItems0{
		Key:   "scenario",
		Value: scenario,
	}
	event.Meta = append(event.Meta, MetaItem)
	events = append(events, event)

	capacity := int32(rand.Intn(20))
	eventsCount := int32(2)
	leakSpeed := "5evt/s"
	message := "test"
	scenarioVersion := fmt.Sprintf("v0.%d", rand.Intn(9))
	scenarioHash := xid.New().String()
	scenarii := fmt.Sprintf("v0.%d", rand.Intn(10))
	simulated := false
	startAt := time.Now().Format(time.RFC3339)
	stopAt := time.Now().Format(time.RFC3339)

	alert := &models.Alert{
		ID:              xid.New().String(),
		Capacity:        &capacity,
		Decisions:       []*models.Decision{decision},
		Events:          events,
		EventsCount:     &eventsCount,
		Labels:          []string{"bf"},
		Leakspeed:       &leakSpeed,
		MachineID:       *m.ID,
		Message:         &message,
		ScenarioHash:    &scenarioHash,
		Scenario:        &scenarii,
		ScenarioVersion: &scenarioVersion,
		Simulated:       &simulated,
		Source: &models.Source{
			AsName:    AS[rand.Intn(len(AS))],
			AsNumber:  fmt.Sprintf("%d", rand.Intn(len(AS))),
			Cn:        Countries[rand.Intn(len(Countries))],
			IP:        ipAddr,
			Latitude:  rand.Float32(),
			Longitude: rand.Float32(),
			Range:     ipRange,
			Scope:     &scope,
			Value:     &ipAddr,
		},
		StartAt: &startAt,
		StopAt:  &stopAt,
	}

	return alert

}

func (m *Machine) Run(apiURL string, nbRequest int, wg *sync.WaitGroup, metrics chan Metrics, bulk bool) {
	var Client *apiclient.ApiClient

	defer wg.Done()

	seed := time.Now().UTC().UnixNano()
	nameGenerator := namegenerator.NewNameGenerator(seed)
	name := nameGenerator.Generate()
	log.Printf("[Process:%s] Running", name)

	ctx := context.Background()

	Client = apiclient.NewClient(nil)
	_, err := Client.Auth.RegisterWatcher(ctx, models.WatcherRegistrationRequest{MachineID: m.ID, Password: m.password})
	if err != nil {
		// machine is already register ?
		log.Errorf("err : %+v \n", err.Error())
	}

	apiclient.BaseURL, _ = url.Parse(apiURL)
	t := &apiclient.JWTTransport{
		MachineID: m.ID,
		Password:  m.password,
		Scenarios: []string{"aaaaaa", "bbbbb"},
	}
	Client = apiclient.NewClient(t.Client())

	log.Printf("[Process:%s] Going to ingest %d alerts", name, nbRequest)

	var duration time.Duration

	if bulk {
		toSend := []*models.Alert{}
		for i := 0; i < nbRequest; i++ {
			alert := m.CreateAlert()
			toSend = append(toSend, alert)
		}
		now := time.Now()
		_, _, err := Client.Alerts.Add(ctx, toSend)
		if err != nil {
			log.Fatalf(err.Error())
		}
		duration = time.Now().Sub(now)

	} else {
		for i := 0; i < nbRequest-1; i++ {
			alert := m.CreateAlert()
			now := time.Now()
			_, _, err := Client.Alerts.Add(ctx, []*models.Alert{alert})
			if err != nil {
				log.Fatalf(err.Error())
			}
			duration += time.Now().Sub(now)
		}
	}
	log.Printf("[Process:%s] Finished: %d alerts sended => '%s'", name, nbRequest, duration)
	metrics <- Metrics{MachineID: *m.ID, NBSend: nbRequest, Time: duration, Bulk: bulk}
}

func main() {
	var wg sync.WaitGroup

	nbMachine := flag.Int("c", 10, "Number of concurrent simulated machines")
	nbRequestPerMachine := flag.Int("n", 100, "Total of request to send by machine")
	bulk := flag.Bool("b", false, "Send all alerts in one request")

	url := flag.String("u", "http://localhost:8080/", "URL of API")
	flag.Parse()

	cleanURL := *url

	if !strings.HasSuffix(cleanURL, "/") {
		cleanURL = fmt.Sprintf("%s/", cleanURL)
	}

	metricsChan := make(chan Metrics, *nbMachine)

	for i := 0; i <= *nbMachine-1; i++ {
		id := fmt.Sprintf(MachineIDTemplate, i)
		password := strfmt.Password("abcdefgh")
		machine := &Machine{
			IPAddress: fmt.Sprintf(machineIPAddrTemplate, rand.Intn(254)),
			ID:        &id,
			password:  &password,
		}
		wg.Add(1)
		go machine.Run(*url, *nbRequestPerMachine, &wg, metricsChan, *bulk)
	}

	wg.Wait()

	log.Printf("All go routines finished")
	close(metricsChan)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")

	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	table.SetHeader([]string{"Machine", "NbRequest Sent", "Bulk", "Time to send"})

	for m := range metricsChan {
		table.Append([]string{m.MachineID, fmt.Sprintf("%d", m.NBSend), fmt.Sprintf("%t", m.Bulk), fmt.Sprintf("%s", m.Time)})
	}

	table.Render()

}
