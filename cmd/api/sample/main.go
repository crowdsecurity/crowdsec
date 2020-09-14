package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/goombaio/namegenerator"
	"github.com/rs/xid"
)

const URL = "http://localhost:8080/"
const machinesURL = URL + "watchers"
const alertsURL = URL + "alerts"
const loginURL = URL + "watchers/login"

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


type Machine struct {
	IPAddress string
	ID        string
	password  string
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
		Duration:   fmt.Sprintf("%d", rand.Intn(4)),
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
		Timestamp: time.Now().String(),
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
		StartAt: time.Now().String(),
		StopAt:  time.Now().String(),
	}

	return alert

}

func (m *Machine) Run(url string, nbRequest int, wg *sync.WaitGroup) {
	var err error
	defer wg.Done()

	var Client *apiclient.ApiClient
	ctx := context.Background()
	apiclient.BaseURL, _ = url.Parse("http://127.0.0.1:8080/")
	t := &apiclient.JWTTransport{
		MachineID: m.ID,
		Password:  m.password,
		Scenarios: []string{"aaaaaa", "bbbbb"},
	}

	seed := time.Now().UTC().UnixNano()
	nameGenerator := namegenerator.NewNameGenerator(seed)
	name := nameGenerator.Generate()
	log.Printf("[Process:%s] Running", name)

	Client = apiclient.NewClient(t.Client())

	for i := 0; i < nbRequest-1; i++ {
		alert := m.CreateAlert()
		_, _, err := Client.Alerts.Add(ctx, alert)
		if err != nil {
			log.Fatalf(err.Error())
		}
	}
	log.Printf("[Process:%s] Finished", name)
}

func main() {
	var wg sync.WaitGroup

	nbMachine := flag.Int("c", 10, "Number of concurrent simulated machines")
	nbRequest := flag.Int("n", 100, "Total number of request to send (distributed by machine)")
	url := flag.String("u", "http://localhost:8080", "URL of API")

	flag.Parse()

	nbRequestPerMachine := *nbRequest / *nbMachine

	for i := 0; i < *nbMachine-1; i++ {
		machine := &Machine{
			IPAddress: fmt.Sprintf(machineIPAddrTemplate, rand.Intn(254)),
			ID:        fmt.Sprintf(MachineIDTemplate, i),
			password:  "abcdefgh",
		}
		wg.Add(1)
		go machine.Run(*url, nbRequestPerMachine, &wg)
	}

	wg.Wait()

	log.Printf("All go routines finished")

}

/*func main() {
	sessions := make(map[string]*Session, 0)
	duration := flag.String("d", "2m", "Default duration is 2 minutes. Supported format (30s, 1m, 4h)")
	flag.Parse()

	jsonFile, err := ioutil.ReadFile("machines.json")
	if err != nil {
		log.Fatalln(err)
	}
	var machines []models.WatcherRegistrationRequest
	err = json.Unmarshal([]byte(jsonFile), &machines)
	if err != nil {
		log.Fatalln(err)
	}

	// Create machines
	for _, machine := range machines {
		b := new(bytes.Buffer)
		json.NewEncoder(b).Encode(machine)
		res, err := http.Post(machinesURL, "application/json;charset=utf-8", b)
		if err != nil {
			log.Fatalln(err)
		}
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		fmt.Printf("%v\n\n", bodyString)
		time.Sleep(1 * time.Second)
	}

	for _, machine := range machines {
		b := new(bytes.Buffer)
		json.NewEncoder(b).Encode(machine)
		res, err := http.Post(loginURL, "application/json;charset=utf-8", b)
		if err != nil {
			log.Fatalln(err)
		}
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
		}
		response := &loginRespone{}
		if err := json.Unmarshal(bodyBytes, response); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Reponse : %+v \n", string(bodyBytes))

		session := &Session{
			Token:     response.Token,
			Expire:    response.Expire,
			MachineID: machine.MachineID,
		}
		sessions[machine.MachineID] = session
	}

	jsonFile, err = ioutil.ReadFile("alerts.json")
	if err != nil {
		log.Fatalln(err)
	}
	var alerts []models.Alert
	err = json.Unmarshal([]byte(jsonFile), &alerts)
	if err != nil {
		log.Fatalln(err)
	}

	for _, alert := range alerts {
		if alert.MachineID == "" {
			log.Fatal("please provide machine_id to push alert")
		}
		if _, ok := sessions[alert.MachineID]; !ok {
			log.Fatal("don't have session for machine '%s' to push alerts", machine.MachineId)
		}
		httpToken := sessions[alert.MachineID].Token
		for _, decision := range alert.Decisions {
			decision.Duration = *duration
		}
		b := new(bytes.Buffer)
		data := []models.Alert{}
		data = append(data, alert)
		json.NewEncoder(b).Encode(data)

		httpClient := &http.Client{}
		req, _ := http.NewRequest("POST", alertsURL, b)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", httpToken))
		req.Header.Set("Content-Type", "application/json;charset=utf-8")
		res, err := httpClient.Do(req)
		if err != nil {
			log.Fatalln(err)
		}

		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		fmt.Printf("%v\n\n", bodyString)
	}
}
*/
