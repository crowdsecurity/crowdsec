package apiclient

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func TestAlertsListAsMachine(t *testing.T) {
	ctx := t.Context()
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
		assert.NoError(t, err)
	})

	log.Printf("URL is %s", urlx)

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	require.NoError(t, err)

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

	tscenario := "crowdsecurity/ssh-bf"
	tscope := "Ip"
	tvalue := "1.1.1.172"
	ttimestamp := "2020-11-28 10:20:46 +0000 UTC"
	tmessage := "Ip 1.1.1.172 performed 'crowdsecurity/ssh-bf' (6 events over 2.920062ms) at 2020-11-28 10:20:46.845619968 +0100 CET m=+5.903899761"

	expected := models.GetAlertsResponse{
		&models.Alert{
			Capacity:  ptr.Of(int32(5)),
			CreatedAt: "2020-11-28T10:20:47+01:00",
			Decisions: []*models.Decision{
				{
					Duration: ptr.Of("59m49.264032632s"),
					ID:       1,
					Origin:   ptr.Of("crowdsec"),
					Scenario: &tscenario,

					Scope:     &tscope,
					Simulated: ptr.Of(false),
					Type:      ptr.Of("ban"),
					Value:     &tvalue,
				},
			},
			Events: []*models.Event{
				{
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
				}, {
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
			EventsCount:     ptr.Of(int32(6)),
			ID:              1,
			Leakspeed:       ptr.Of("10s"),
			MachineID:       "test",
			Message:         &tmessage,
			Remediation:     false,
			Scenario:        &tscenario,
			ScenarioHash:    ptr.Of("4441dcff07020f6690d998b7101e642359ba405c2abb83565bbbdcee36de280f"),
			ScenarioVersion: ptr.Of("0.1"),
			Simulated:       ptr.Of(false),
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
			StartAt: ptr.Of("2020-11-28 10:20:46.842701127 +0100 +0100"),
			StopAt:  ptr.Of("2020-11-28 10:20:46.845621385 +0100 +0100"),
		},
	}

	// log.Debugf("data : -> %s", spew.Sdump(alerts))
	// log.Debugf("resp : -> %s", spew.Sdump(resp))
	// log.Debugf("expected : -> %s", spew.Sdump(expected))
	// first one returns data
	alerts, resp, err := client.Alerts.List(ctx, AlertsListOpts{})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)
	assert.Equal(t, expected, *alerts)

	// this one doesn't
	filter := AlertsListOpts{IPEquals: ptr.Of("1.2.3.4")}

	alerts, resp, err = client.Alerts.List(ctx, filter)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)
	assert.Empty(t, *alerts)
}

func TestAlertsGetAsMachine(t *testing.T) {
	ctx := t.Context()
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
		assert.NoError(t, err)
	})
	log.Printf("URL is %s", urlx)

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	require.NoError(t, err)

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

	tscenario := "crowdsecurity/ssh-bf"
	tscope := "Ip"
	ttype := "ban"
	tvalue := "1.1.1.172"
	ttimestamp := "2020-11-28 10:20:46 +0000 UTC"

	expected := &models.Alert{
		Capacity:  ptr.Of(int32(5)),
		CreatedAt: "2020-11-28T10:20:47+01:00",
		Decisions: []*models.Decision{
			{
				Duration: ptr.Of("59m49.264032632s"),
				ID:       1,
				Origin:   ptr.Of("crowdsec"),
				Scenario: &tscenario,

				Scope:     &tscope,
				Simulated: ptr.Of(false),
				Type:      &ttype,
				Value:     &tvalue,
			},
		},
		Events: []*models.Event{
			{
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
			}, {
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
		EventsCount:     ptr.Of(int32(6)),
		ID:              1,
		Leakspeed:       ptr.Of("10s"),
		MachineID:       "test",
		Message:         ptr.Of("Ip 1.1.1.172 performed 'crowdsecurity/ssh-bf' (6 events over 2.920062ms) at 2020-11-28 10:20:46.845619968 +0100 CET m=+5.903899761"),
		Remediation:     false,
		Scenario:        &tscenario,
		ScenarioHash:    ptr.Of("4441dcff07020f6690d998b7101e642359ba405c2abb83565bbbdcee36de280f"),
		ScenarioVersion: ptr.Of("0.1"),
		Simulated:       ptr.Of(false),
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
		StartAt: ptr.Of("2020-11-28 10:20:46.842701127 +0100 +0100"),
		StopAt:  ptr.Of("2020-11-28 10:20:46.845621385 +0100 +0100"),
	}

	alerts, resp, err := client.Alerts.GetByID(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)
	assert.Equal(t, *expected, *alerts)

	// fail
	_, _, err = client.Alerts.GetByID(ctx, 2)
	cstest.RequireErrorMessage(t, err, "API error: object not found")
}

func TestAlertsCreateAsMachine(t *testing.T) {
	ctx := t.Context()
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
		assert.NoError(t, err)
	})

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`["3"]`))
		assert.NoError(t, err)
	})

	log.Printf("URL is %s", urlx)

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	require.NoError(t, err)

	defer teardown()

	alert := models.AddAlertsRequest{}
	alerts, resp, err := client.Alerts.Add(ctx, alert)
	require.NoError(t, err)

	expected := &models.AddAlertsResponse{"3"}

	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)
	assert.Equal(t, *expected, *alerts)
}

func TestAlertsDeleteAsMachine(t *testing.T) {
	ctx := t.Context()
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
		assert.NoError(t, err)
	})

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "DELETE")
		assert.Equal(t, "ip=1.2.3.4", r.URL.RawQuery)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"message":"0 deleted alerts"}`))
		assert.NoError(t, err)
	})

	log.Printf("URL is %s", urlx)

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		URL:           apiURL,
		VersionPrefix: "v1",
	})
	require.NoError(t, err)

	defer teardown()

	alert := AlertsDeleteOpts{IPEquals: ptr.Of("1.2.3.4")}
	alerts, resp, err := client.Alerts.Delete(ctx, alert)
	require.NoError(t, err)

	expected := &models.DeleteAlertsResponse{NbDeleted: ""}

	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)
	assert.Equal(t, *expected, *alerts)
}
