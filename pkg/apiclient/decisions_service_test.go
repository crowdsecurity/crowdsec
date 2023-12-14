package apiclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/modelscapi"
)

func TestDecisionsList(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	defer teardown()

	mux.HandleFunc("/decisions", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		if r.URL.RawQuery == "ip=1.2.3.4" {
			assert.Equal(t, "ip=1.2.3.4", r.URL.RawQuery)
			assert.Equal(t, "ixu", r.Header.Get("X-Api-Key"))
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"duration":"3h59m55.756182786s","id":4,"origin":"cscli","scenario":"manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'","scope":"Ip","type":"ban","value":"1.2.3.4"}]`))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`null`))
			//no results
		}
	})
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	//ok answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v1", "toto", auth.Client())
	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	tduration := "3h59m55.756182786s"
	torigin := "cscli"
	tscenario := "manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'"
	tscope := "Ip"
	ttype := "ban"
	tvalue := "1.2.3.4"
	expected := &models.GetDecisionsResponse{
		&models.Decision{
			Duration: &tduration,
			ID:       4,
			Origin:   &torigin,
			Scenario: &tscenario,
			Scope:    &tscope,
			Type:     &ttype,
			Value:    &tvalue,
		},
	}

	//OK decisions
	decisionsFilter := DecisionsListOpts{IPEquals: new(string)}
	*decisionsFilter.IPEquals = "1.2.3.4"
	decisions, resp, err := newcli.Decisions.List(context.Background(), decisionsFilter)

	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}

	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	if !reflect.DeepEqual(*decisions, *expected) {
		t.Fatalf("returned %+v, want %+v", resp, expected)
	}

	//Empty return
	decisionsFilter = DecisionsListOpts{IPEquals: new(string)}
	*decisionsFilter.IPEquals = "1.2.3.5"
	decisions, resp, err = newcli.Decisions.List(context.Background(), decisionsFilter)
	require.NoError(t, err)

	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}

	assert.Empty(t, *decisions)
}

func TestDecisionsStream(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	defer teardown()

	mux.HandleFunc("/decisions/stream", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "ixu", r.Header.Get("X-Api-Key"))
		testMethod(t, r, http.MethodGet)
		if r.Method == http.MethodGet {
			if r.URL.RawQuery == "startup=true" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"deleted":null,"new":[{"duration":"3h59m55.756182786s","id":4,"origin":"cscli","scenario":"manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'","scope":"Ip","type":"ban","value":"1.2.3.4"}]}`))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"deleted":null,"new":null}`))
			}
		}
	})
	mux.HandleFunc("/decisions", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "ixu", r.Header.Get("X-Api-Key"))
		testMethod(t, r, http.MethodDelete)
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
		}
	})

	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	//ok answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v1", "toto", auth.Client())
	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	tduration := "3h59m55.756182786s"
	torigin := "cscli"
	tscenario := "manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'"
	tscope := "Ip"
	ttype := "ban"
	tvalue := "1.2.3.4"
	expected := &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			&models.Decision{
				Duration: &tduration,
				ID:       4,
				Origin:   &torigin,
				Scenario: &tscenario,
				Scope:    &tscope,
				Type:     &ttype,
				Value:    &tvalue,
			},
		},
	}

	decisions, resp, err := newcli.Decisions.GetStream(context.Background(), DecisionsStreamOpts{Startup: true})
	require.NoError(t, err)

	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}

	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	if !reflect.DeepEqual(*decisions, *expected) {
		t.Fatalf("returned %+v, want %+v", resp, expected)
	}

	//and second call, we get empty lists
	decisions, resp, err = newcli.Decisions.GetStream(context.Background(), DecisionsStreamOpts{Startup: false})
	require.NoError(t, err)

	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}

	assert.Empty(t, decisions.New)
	assert.Empty(t, decisions.Deleted)

	//delete stream
	resp, err = newcli.Decisions.StopStream(context.Background())
	require.NoError(t, err)

	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}
}

func TestDecisionsStreamV3Compatibility(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setupWithPrefix("v3")
	defer teardown()

	mux.HandleFunc("/decisions/stream", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "ixu", r.Header.Get("X-Api-Key"))
		testMethod(t, r, http.MethodGet)
		if r.Method == http.MethodGet {
			if r.URL.RawQuery == "startup=true" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"deleted":[{"scope":"ip","decisions":["1.2.3.5"]}],"new":[{"scope":"ip", "scenario": "manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'", "decisions":[{"duration":"3h59m55.756182786s","value":"1.2.3.4"}]}]}`))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"deleted":null,"new":null}`))
			}
		}
	})

	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	//ok answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v3", "toto", auth.Client())
	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	tduration := "3h59m55.756182786s"
	torigin := "CAPI"
	tscenario := "manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'"
	tscope := "ip"
	ttype := "ban"
	tvalue := "1.2.3.4"
	tvalue1 := "1.2.3.5"
	tscenarioDeleted := "deleted"
	tdurationDeleted := "1h"
	expected := &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			&models.Decision{
				Duration: &tduration,
				Origin:   &torigin,
				Scenario: &tscenario,
				Scope:    &tscope,
				Type:     &ttype,
				Value:    &tvalue,
			},
		},
		Deleted: models.GetDecisionsResponse{
			&models.Decision{
				Duration: &tdurationDeleted,
				Origin:   &torigin,
				Scenario: &tscenarioDeleted,
				Scope:    &tscope,
				Type:     &ttype,
				Value:    &tvalue1,
			},
		},
	}

	// GetStream is supposed to consume v3 payload and return v2 response
	decisions, resp, err := newcli.Decisions.GetStream(context.Background(), DecisionsStreamOpts{Startup: true})
	require.NoError(t, err)

	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}

	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	if !reflect.DeepEqual(*decisions, *expected) {
		t.Fatalf("returned %+v, want %+v", resp, expected)
	}
}

func TestDecisionsStreamV3(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setupWithPrefix("v3")
	defer teardown()

	mux.HandleFunc("/decisions/stream", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "ixu", r.Header.Get("X-Api-Key"))
		testMethod(t, r, http.MethodGet)
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"deleted":[{"scope":"ip","decisions":["1.2.3.5"]}],
			"new":[{"scope":"ip", "scenario": "manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'", "decisions":[{"duration":"3h59m55.756182786s","value":"1.2.3.4"}]}],
			"links": {"blocklists":[{"name":"blocklist1","url":"/v3/blocklist","scope":"ip","remediation":"ban","duration":"24h"}]}}`))
		}
	})

	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	//ok answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v3", "toto", auth.Client())
	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	tduration := "3h59m55.756182786s"
	tscenario := "manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'"
	tscope := "ip"
	tvalue := "1.2.3.4"
	tvalue1 := "1.2.3.5"
	tdurationBlocklist := "24h"
	tnameBlocklist := "blocklist1"
	tremediationBlocklist := "ban"
	tscopeBlocklist := "ip"
	turlBlocklist := "/v3/blocklist"
	expected := &modelscapi.GetDecisionsStreamResponse{
		New: modelscapi.GetDecisionsStreamResponseNew{
			&modelscapi.GetDecisionsStreamResponseNewItem{
				Decisions: []*modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{
					{
						Duration: &tduration,
						Value:    &tvalue,
					},
				},
				Scenario: &tscenario,
				Scope:    &tscope,
			},
		},
		Deleted: modelscapi.GetDecisionsStreamResponseDeleted{
			&modelscapi.GetDecisionsStreamResponseDeletedItem{
				Scope: &tscope,
				Decisions: []string{
					tvalue1,
				},
			},
		},
		Links: &modelscapi.GetDecisionsStreamResponseLinks{
			Blocklists: []*modelscapi.BlocklistLink{
				{
					Duration:    &tdurationBlocklist,
					Name:        &tnameBlocklist,
					Remediation: &tremediationBlocklist,
					Scope:       &tscopeBlocklist,
					URL:         &turlBlocklist,
				},
			},
		},
	}

	// GetStream is supposed to consume v3 payload and return v2 response
	decisions, resp, err := newcli.Decisions.GetStreamV3(context.Background(), DecisionsStreamOpts{Startup: true})
	require.NoError(t, err)

	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}

	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	if !reflect.DeepEqual(*decisions, *expected) {
		t.Fatalf("returned %+v, want %+v", resp, expected)
	}
}

func TestDecisionsFromBlocklist(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setupWithPrefix("v3")
	defer teardown()

	mux.HandleFunc("/blocklist", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		if r.Header.Get("If-Modified-Since") == "Sun, 01 Jan 2023 01:01:01 GMT" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("1.2.3.4\r\n1.2.3.5"))
		}
	})

	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	//ok answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v3", "toto", auth.Client())
	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	tvalue1 := "1.2.3.4"
	tvalue2 := "1.2.3.5"
	tdurationBlocklist := "24h"
	tnameBlocklist := "blocklist1"
	tremediationBlocklist := "ban"
	tscopeBlocklist := "ip"
	turlBlocklist := urlx + "/v3/blocklist"
	torigin := "lists"
	expected := []*models.Decision{
		{
			Duration: &tdurationBlocklist,
			Value:    &tvalue1,
			Scenario: &tnameBlocklist,
			Scope:    &tscopeBlocklist,
			Type:     &tremediationBlocklist,
			Origin:   &torigin,
		},
		{
			Duration: &tdurationBlocklist,
			Value:    &tvalue2,
			Scenario: &tnameBlocklist,
			Scope:    &tscopeBlocklist,
			Type:     &tremediationBlocklist,
			Origin:   &torigin,
		},
	}
	decisions, isModified, err := newcli.Decisions.GetDecisionsFromBlocklist(context.Background(), &modelscapi.BlocklistLink{
		URL:         &turlBlocklist,
		Scope:       &tscopeBlocklist,
		Remediation: &tremediationBlocklist,
		Name:        &tnameBlocklist,
		Duration:    &tdurationBlocklist,
	}, nil)
	require.NoError(t, err)
	assert.True(t, isModified)

	log.Infof("decision1: %+v", decisions[0])
	log.Infof("expected1: %+v", expected[0])
	log.Infof("decisions: %s, %s, %s, %s, %s, %s", *decisions[0].Value, *decisions[0].Duration, *decisions[0].Scenario, *decisions[0].Scope, *decisions[0].Type, *decisions[0].Origin)
	log.Infof("expected : %s, %s, %s, %s, %s", *expected[0].Value, *expected[0].Duration, *expected[0].Scenario, *expected[0].Scope, *expected[0].Type)
	log.Infof("decisions: %s, %s, %s, %s, %s", *decisions[1].Value, *decisions[1].Duration, *decisions[1].Scenario, *decisions[1].Scope, *decisions[1].Type)

	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	if !reflect.DeepEqual(decisions, expected) {
		t.Fatalf("returned %+v, want %+v", decisions, expected)
	}

	// test cache control
	_, isModified, err = newcli.Decisions.GetDecisionsFromBlocklist(context.Background(), &modelscapi.BlocklistLink{
		URL:         &turlBlocklist,
		Scope:       &tscopeBlocklist,
		Remediation: &tremediationBlocklist,
		Name:        &tnameBlocklist,
		Duration:    &tdurationBlocklist,
	}, ptr.Of("Sun, 01 Jan 2023 01:01:01 GMT"))
	require.NoError(t, err)
	assert.False(t, isModified)
	_, isModified, err = newcli.Decisions.GetDecisionsFromBlocklist(context.Background(), &modelscapi.BlocklistLink{
		URL:         &turlBlocklist,
		Scope:       &tscopeBlocklist,
		Remediation: &tremediationBlocklist,
		Name:        &tnameBlocklist,
		Duration:    &tdurationBlocklist,
	}, ptr.Of("Mon, 02 Jan 2023 01:01:01 GMT"))
	require.NoError(t, err)
	assert.True(t, isModified)
}

func TestDeleteDecisions(t *testing.T) {
	mux, urlx, teardown := setup()
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
	})
	mux.HandleFunc("/decisions", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "DELETE")
		assert.Equal(t, "ip=1.2.3.4", r.URL.RawQuery)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"nbDeleted":"1"}`))
		//w.Write([]byte(`{"message":"0 deleted alerts"}`))
	})
	log.Printf("URL is %s", urlx)
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}
	client, err := NewClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", version.String()),
		URL:           apiURL,
		VersionPrefix: "v1",
	})

	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	filters := DecisionsDeleteOpts{IPEquals: new(string)}
	*filters.IPEquals = "1.2.3.4"
	deleted, _, err := client.Decisions.Delete(context.Background(), filters)
	if err != nil {
		t.Fatalf("unexpected err : %s", err)
	}

	assert.Equal(t, "1", deleted.NbDeleted)

	defer teardown()
}

func TestDecisionsStreamOpts_addQueryParamsToURL(t *testing.T) {
	baseURLString := "http://localhost:8080/v1/decisions/stream"

	type fields struct {
		Startup                bool
		Scopes                 string
		ScenariosContaining    string
		ScenariosNotContaining string
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name: "no filter",
			want: baseURLString + "?",
		},
		{
			name: "startup=true",
			fields: fields{
				Startup: true,
			},
			want: baseURLString + "?startup=true",
		},
		{
			name: "set all params",
			fields: fields{
				Startup:                true,
				Scopes:                 "ip,range",
				ScenariosContaining:    "ssh",
				ScenariosNotContaining: "bf",
			},
			want: baseURLString + "?scenarios_containing=ssh&scenarios_not_containing=bf&scopes=ip%2Crange&startup=true",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			o := &DecisionsStreamOpts{
				Startup:                tt.fields.Startup,
				Scopes:                 tt.fields.Scopes,
				ScenariosContaining:    tt.fields.ScenariosContaining,
				ScenariosNotContaining: tt.fields.ScenariosNotContaining,
			}
			got, err := o.addQueryParamsToURL(baseURLString)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecisionsStreamOpts.addQueryParamsToURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			gotURL, err := url.Parse(got)
			if err != nil {
				t.Errorf("DecisionsStreamOpts.addQueryParamsToURL() got error while parsing URL: %s", err)
			}

			expectedURL, err := url.Parse(tt.want)
			if err != nil {
				t.Errorf("DecisionsStreamOpts.addQueryParamsToURL() got error while parsing URL: %s", err)
			}

			if *gotURL != *expectedURL {
				t.Errorf("DecisionsStreamOpts.addQueryParamsToURL() = %v, want %v", *gotURL, *expectedURL)
			}
		})
	}
}

// func TestDeleteOneDecision(t *testing.T) {
// 	mux, urlx, teardown := setup()
// 	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
// 		w.WriteHeader(http.StatusOK)
// 		w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
// 	})
// 	mux.HandleFunc("/decisions/1", func(w http.ResponseWriter, r *http.Request) {
// 		testMethod(t, r, "DELETE")
// 		w.WriteHeader(http.StatusOK)
// 		w.Write([]byte(`{"nbDeleted":"1"}`))
// 	})
// 	log.Printf("URL is %s", urlx)
// 	apiURL, err := url.Parse(urlx + "/")
// 	if err != nil {
// 		t.Fatalf("parsing api url: %s", apiURL)
// 	}
// 	client, err := NewClient(&Config{
// 		MachineID:     "test_login",
// 		Password:      "test_password",
// 		UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
// 		URL:           apiURL,
// 		VersionPrefix: "v1",
// 	})

// 	if err != nil {
// 		t.Fatalf("new api client: %s", err)
// 	}

// 	filters := DecisionsDeleteOpts{IPEquals: new(string)}
// 	*filters.IPEquals = "1.2.3.4"
// 	deleted, _, err := client.Decisions.Delete(context.Background(), filters)
// 	if err != nil {
// 		t.Fatalf("unexpected err : %s", err)
// 	}
// 	assert.Equal(t, "1", deleted.NbDeleted)

// 	defer teardown()
// }
