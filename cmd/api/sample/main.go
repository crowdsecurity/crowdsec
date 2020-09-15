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
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/goombaio/namegenerator"
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
	ID        string
	password  string
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

	decision := &models.Decision{
		DecisionID: guid.String(),
		Duration:   fmt.Sprintf("%dh", rand.Intn(4)),
		EndIP:      endIP,
		StartIP:    startIP,
		Origin:     "crowdsec",
		Scenario:   scenario,
		Scope:      "ip",
		Target:     ipAddr,
		Type:       "ban",
	}

	events := []*models.Event{}
	event := &models.Event{
		Meta:      models.Meta{},
		Timestamp: time.Now().Format(time.RFC3339),
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

	alert := &models.Alert{
		AlertID:      xid.New().String(),
		Capacity:     int32(rand.Intn(20)),
		Decisions:    []*models.Decision{decision},
		Events:       events,
		EventsCount:  2,
		Labels:       []string{"bf"},
		Leakspeed:    "5evt/s",
		MachineID:    m.ID,
		Message:      "test",
		ScenarioHash: xid.New().String(),
		Scenario:     fmt.Sprintf("v0.%d", rand.Intn(10)),
		Simulated:    false,
		Source: &models.Source{
			AsName:    AS[rand.Intn(len(AS))],
			AsNumber:  fmt.Sprintf("%d", rand.Intn(len(AS))),
			Cn:        Countries[rand.Intn(len(Countries))],
			IP:        ipAddr,
			Latitude:  rand.Float32(),
			Longitude: rand.Float32(),
			Range:     ipRange,
			Scope:     "ip",
			Value:     ipAddr,
		},
		StartAt: time.Now().Format(time.RFC3339),
		StopAt:  time.Now().Format(time.RFC3339),
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
		for i := 0; i < nbRequest-1; i++ {
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
	metrics <- Metrics{MachineID: m.ID, NBSend: nbRequest, Time: duration, Bulk: bulk}
}

func main() {
	var wg sync.WaitGroup

	nbMachine := flag.Int("c", 10, "Number of concurrent simulated machines")
	//nbRequest := flag.Int("n", 100, "Total number of request to send (distributed by machine)")
	nbRequestPerMachine := flag.Int("n", 100, "Total of request to send by machine")
	bulk := flag.Bool("b", false, "Send all alerts in one request")

	url := flag.String("u", "http://localhost:8080/", "URL of API")
	flag.Parse()

	cleanURL := *url

	if !strings.HasSuffix(cleanURL, "/") {
		cleanURL = fmt.Sprintf("%s/", cleanURL)
	}

	//nbRequestPerMachine := *nbRequest / *nbMachine

	metricsChan := make(chan Metrics, *nbMachine)

	for i := 0; i <= *nbMachine-1; i++ {
		machine := &Machine{
			IPAddress: fmt.Sprintf(machineIPAddrTemplate, rand.Intn(254)),
			ID:        fmt.Sprintf(MachineIDTemplate, i),
			password:  "abcdefgh",
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
