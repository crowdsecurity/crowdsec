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

func TestDecisionsList(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	defer teardown()

	mux.HandleFunc("/decisions", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		if r.URL.RawQuery == "ip=1.2.3.4" {
			assert.Equal(t, r.URL.RawQuery, "ip=1.2.3.4")
			assert.Equal(t, r.Header.Get("X-Api-Key"), "ixu")
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
	assert.Equal(t, len(*decisions), 0)

}

func TestDecisionsStream(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	defer teardown()

	mux.HandleFunc("/decisions/stream", func(w http.ResponseWriter, r *http.Request) {

		assert.Equal(t, r.Header.Get("X-Api-Key"), "ixu")
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
		assert.Equal(t, r.Header.Get("X-Api-Key"), "ixu")
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
	assert.Equal(t, 0, len(decisions.New))
	assert.Equal(t, 0, len(decisions.Deleted))

	//delete stream
	resp, err = newcli.Decisions.StopStream(context.Background())
	require.NoError(t, err)

	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}
}

func TestDeleteDecisions(t *testing.T) {
	mux, urlx, teardown := setup()
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
	})
	mux.HandleFunc("/decisions", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "DELETE")
		assert.Equal(t, r.URL.RawQuery, "ip=1.2.3.4")
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
		UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
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
