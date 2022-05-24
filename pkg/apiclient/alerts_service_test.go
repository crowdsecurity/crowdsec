package apiclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlertsListAsMachine(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
	})
	log.Printf("URL is %s", urlx)
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		log.Fatalf("parsing api url: %s", apiURL)
	}
	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		URL:           apiURL,
		VersionPrefix: "v1",
	})

	if err != nil {
		log.Fatalf("new api client: %s", err.Error())
	}

	defer teardown()

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {

		if r.URL.RawQuery == "ip=1.2.3.4" {
			testMethod(t, r, "GET")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `null`)
			return
		}

		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `[
			{"capacity":5,"created_at":"2020-11-28T10:20:47+01:00",
			 "decisions":[
				  {"duration":"59m49.264032632s",
				  "id":1,
				  "origin":"crowdsec",
				  "scenario":"crowdsecurity/ssh-bf",
				  "scope":"Ip",
				  "simulated":false,
				  "type":"ban",
				  "value":"1.1.1.172"}
				  ],
			 "events":[
				 {"meta":[
					  {"key":"target_user","value":"netflix"},
					  {"key":"service","value":"ssh"}
					],
					"timestamp":"2020-11-28 10:20:46 +0000 UTC"},
				 {"meta":[
					 {"key":"target_user","value":"netflix"},
					 {"key":"service","value":"ssh"}
					 ],
					 "timestamp":"2020-11-28 10:20:46 +0000 UTC"}
				],
				"events_count":6,
				"id":1,
				"labels":null,
				"leakspeed":"10s",
				"machine_id":"test",
				"message":"Ip 1.1.1.172 performed 'crowdsecurity/ssh-bf' (6 events over 2.920062ms) at 2020-11-28 10:20:46.845619968 +0100 CET m=+5.903899761",
				"scenario":"crowdsecurity/ssh-bf",
				"scenario_hash":"4441dcff07020f6690d998b7101e642359ba405c2abb83565bbbdcee36de280f",
				"scenario_version":"0.1",
				"simulated":false,
				"source":{
					"as_name":"Cloudflare Inc",
					"cn":"AU",
					"ip":"1.1.1.172",
					"latitude":-37.7,
					"longitude":145.1833,
					"range":"1.1.1.0/24",
					"scope":"Ip",
					"value":"1.1.1.172"
					},
				"start_at":"2020-11-28 10:20:46.842701127 +0100 +0100",
				"stop_at":"2020-11-28 10:20:46.845621385 +0100 +0100"
			}
		]`)
	})

	tcapacity := int32(5)
	tduration := "59m49.264032632s"
	torigin := "crowdsec"
	tscenario := "crowdsecurity/ssh-bf"
	tscope := "Ip"
	ttype := "ban"
	tvalue := "1.1.1.172"
	ttimestamp := "2020-11-28 10:20:46 +0000 UTC"
	teventscount := int32(6)
	tleakspeed := "10s"
	tmessage := "Ip 1.1.1.172 performed 'crowdsecurity/ssh-bf' (6 events over 2.920062ms) at 2020-11-28 10:20:46.845619968 +0100 CET m=+5.903899761"
	tscenariohash := "4441dcff07020f6690d998b7101e642359ba405c2abb83565bbbdcee36de280f"
	tscenarioversion := "0.1"
	tstartat := "2020-11-28 10:20:46.842701127 +0100 +0100"
	tstopat := "2020-11-28 10:20:46.845621385 +0100 +0100"

	expected := models.GetAlertsResponse{
		&models.Alert{
			Capacity:  &tcapacity,
			CreatedAt: "2020-11-28T10:20:47+01:00",
			Decisions: []*models.Decision{
				&models.Decision{
					Duration: &tduration,
					ID:       1,
					Origin:   &torigin,
					Scenario: &tscenario,

					Scope:     &tscope,
					Simulated: new(bool), //false,
					Type:      &ttype,
					Value:     &tvalue,
				},
			},
			Events: []*models.Event{
				&models.Event{
					Meta: models.Meta{
						&models.MetaItems0{
							Key:   "target_user",
							Value: "netflix",
						},
						&models.MetaItems0{
							Key:   "service",
							Value: "ssh",
						},
					},
					Timestamp: &ttimestamp,
				},
				&models.Event{
					Meta: models.Meta{
						&models.MetaItems0{
							Key:   "target_user",
							Value: "netflix",
						},
						&models.MetaItems0{
							Key:   "service",
							Value: "ssh",
						},
					},
					Timestamp: &ttimestamp,
				},
			},
			EventsCount:     &teventscount,
			ID:              1,
			Leakspeed:       &tleakspeed,
			MachineID:       "test",
			Message:         &tmessage,
			Remediation:     false,
			Scenario:        &tscenario,
			ScenarioHash:    &tscenariohash,
			ScenarioVersion: &tscenarioversion,
			Simulated:       new(bool), //(false),
			Source: &models.Source{
				AsName:    "Cloudflare Inc",
				AsNumber:  "",
				Cn:        "AU",
				IP:        "1.1.1.172",
				Latitude:  -37.7,
				Longitude: 145.1833,
				Range:     "1.1.1.0/24",
				Scope:     &tscope,
				Value:     &tvalue,
			},
			StartAt: &tstartat,
			StopAt:  &tstopat,
		},
	}

	//log.Debugf("data : -> %s", spew.Sdump(alerts))
	//log.Debugf("resp : -> %s", spew.Sdump(resp))
	//log.Debugf("expected : -> %s", spew.Sdump(expected))
	//first one returns data
	alerts, resp, err := client.Alerts.List(context.Background(), AlertsListOpts{})
	if err != nil {
		log.Errorf("test Unable to list alerts : %+v", err)
	}
	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}

	if !reflect.DeepEqual(*alerts, expected) {
		t.Errorf("client.Alerts.List returned %+v, want %+v", resp, expected)
	}
	//this one doesn't
	filter := AlertsListOpts{IPEquals: new(string)}
	*filter.IPEquals = "1.2.3.4"
	alerts, resp, err = client.Alerts.List(context.Background(), filter)
	if err != nil {
		log.Errorf("test Unable to list alerts : %+v", err)
	}
	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}
	assert.Equal(t, 0, len(*alerts))
}

func TestAlertsGetAsMachine(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
	})
	log.Printf("URL is %s", urlx)
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		log.Fatalf("parsing api url: %s", apiURL)
	}
	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		URL:           apiURL,
		VersionPrefix: "v1",
	})

	if err != nil {
		log.Fatalf("new api client: %s", err.Error())
	}

	defer teardown()
	mux.HandleFunc("/alerts/2", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"message":"object not found"}`)
	})

	mux.HandleFunc("/alerts/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"capacity":5,"created_at":"2020-11-28T10:20:47+01:00",
			 "decisions":[
				  {"duration":"59m49.264032632s",
				  "end_ip":16843180,
				  "id":1,
				  "origin":"crowdsec",
				  "scenario":"crowdsecurity/ssh-bf",
				  "scope":"Ip",
				  "simulated":false,
				  "start_ip":16843180,
				  "type":"ban",
				  "value":"1.1.1.172"}
				  ],
			 "events":[
				 {"meta":[
					  {"key":"target_user","value":"netflix"},
					  {"key":"service","value":"ssh"}
					],
					"timestamp":"2020-11-28 10:20:46 +0000 UTC"},
				 {"meta":[
					 {"key":"target_user","value":"netflix"},
					 {"key":"service","value":"ssh"}
					 ],
					 "timestamp":"2020-11-28 10:20:46 +0000 UTC"}
				],
				"events_count":6,
				"id":1,
				"labels":null,
				"leakspeed":"10s",
				"machine_id":"test",
				"message":"Ip 1.1.1.172 performed 'crowdsecurity/ssh-bf' (6 events over 2.920062ms) at 2020-11-28 10:20:46.845619968 +0100 CET m=+5.903899761",
				"scenario":"crowdsecurity/ssh-bf",
				"scenario_hash":"4441dcff07020f6690d998b7101e642359ba405c2abb83565bbbdcee36de280f",
				"scenario_version":"0.1",
				"simulated":false,
				"source":{
					"as_name":"Cloudflare Inc",
					"cn":"AU",
					"ip":"1.1.1.172",
					"latitude":-37.7,
					"longitude":145.1833,
					"range":"1.1.1.0/24",
					"scope":"Ip",
					"value":"1.1.1.172"
					},
				"start_at":"2020-11-28 10:20:46.842701127 +0100 +0100",
				"stop_at":"2020-11-28 10:20:46.845621385 +0100 +0100"
			}`)
	})

	tcapacity := int32(5)
	tduration := "59m49.264032632s"
	torigin := "crowdsec"
	tscenario := "crowdsecurity/ssh-bf"
	tscope := "Ip"
	ttype := "ban"
	tvalue := "1.1.1.172"
	ttimestamp := "2020-11-28 10:20:46 +0000 UTC"
	teventscount := int32(6)
	tleakspeed := "10s"
	tmessage := "Ip 1.1.1.172 performed 'crowdsecurity/ssh-bf' (6 events over 2.920062ms) at 2020-11-28 10:20:46.845619968 +0100 CET m=+5.903899761"
	tscenariohash := "4441dcff07020f6690d998b7101e642359ba405c2abb83565bbbdcee36de280f"
	tscenarioversion := "0.1"
	tstartat := "2020-11-28 10:20:46.842701127 +0100 +0100"
	tstopat := "2020-11-28 10:20:46.845621385 +0100 +0100"

	expected := &models.Alert{
		Capacity:  &tcapacity,
		CreatedAt: "2020-11-28T10:20:47+01:00",
		Decisions: []*models.Decision{
			&models.Decision{
				Duration: &tduration,
				ID:       1,
				Origin:   &torigin,
				Scenario: &tscenario,

				Scope:     &tscope,
				Simulated: new(bool), //false,
				Type:      &ttype,
				Value:     &tvalue,
			},
		},
		Events: []*models.Event{
			&models.Event{
				Meta: models.Meta{
					&models.MetaItems0{
						Key:   "target_user",
						Value: "netflix",
					},
					&models.MetaItems0{
						Key:   "service",
						Value: "ssh",
					},
				},
				Timestamp: &ttimestamp,
			},
			&models.Event{
				Meta: models.Meta{
					&models.MetaItems0{
						Key:   "target_user",
						Value: "netflix",
					},
					&models.MetaItems0{
						Key:   "service",
						Value: "ssh",
					},
				},
				Timestamp: &ttimestamp,
			},
		},
		EventsCount:     &teventscount,
		ID:              1,
		Leakspeed:       &tleakspeed,
		MachineID:       "test",
		Message:         &tmessage,
		Remediation:     false,
		Scenario:        &tscenario,
		ScenarioHash:    &tscenariohash,
		ScenarioVersion: &tscenarioversion,
		Simulated:       new(bool), //(false),
		Source: &models.Source{
			AsName:    "Cloudflare Inc",
			AsNumber:  "",
			Cn:        "AU",
			IP:        "1.1.1.172",
			Latitude:  -37.7,
			Longitude: 145.1833,
			Range:     "1.1.1.0/24",
			Scope:     &tscope,
			Value:     &tvalue,
		},
		StartAt: &tstartat,
		StopAt:  &tstopat,
	}

	alerts, resp, err := client.Alerts.GetByID(context.Background(), 1)
	require.NoError(t, err)
	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}

	if !reflect.DeepEqual(*alerts, *expected) {
		t.Errorf("client.Alerts.List returned %+v, want %+v", resp, expected)
	}

	//fail
	_, resp, err = client.Alerts.GetByID(context.Background(), 2)
	assert.Contains(t, fmt.Sprintf("%s", err), "API error: object not found")

}

func TestAlertsCreateAsMachine(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
	})
	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`["3"]`))
	})
	log.Printf("URL is %s", urlx)
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		log.Fatalf("parsing api url: %s", apiURL)
	}
	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		URL:           apiURL,
		VersionPrefix: "v1",
	})

	if err != nil {
		log.Fatalf("new api client: %s", err.Error())
	}

	defer teardown()
	alert := models.AddAlertsRequest{}
	alerts, resp, err := client.Alerts.Add(context.Background(), alert)
	require.NoError(t, err)
	expected := &models.AddAlertsResponse{"3"}
	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}
	if !reflect.DeepEqual(*alerts, *expected) {
		t.Errorf("client.Alerts.List returned %+v, want %+v", resp, expected)
	}
}

func TestAlertsDeleteAsMachine(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
	})
	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "DELETE")
		assert.Equal(t, r.URL.RawQuery, "ip=1.2.3.4")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"0 deleted alerts"}`))
	})
	log.Printf("URL is %s", urlx)
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		log.Fatalf("parsing api url: %s", apiURL)
	}
	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		URL:           apiURL,
		VersionPrefix: "v1",
	})

	if err != nil {
		log.Fatalf("new api client: %s", err.Error())
	}

	defer teardown()
	alert := AlertsDeleteOpts{IPEquals: new(string)}
	*alert.IPEquals = "1.2.3.4"
	alerts, resp, err := client.Alerts.Delete(context.Background(), alert)
	require.NoError(t, err)

	expected := &models.DeleteAlertsResponse{""}
	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}
	if !reflect.DeepEqual(*alerts, *expected) {
		t.Errorf("client.Alerts.List returned %+v, want %+v", resp, expected)
	}
}
