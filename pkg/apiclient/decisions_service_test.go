package apiclient

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestDecisionsList(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	_, mux, urlx, teardown := setup()
	defer teardown()

	mux.HandleFunc("/decisions", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		if r.URL.RawQuery == "ip=1.2.3.4" {
			assert.Equal(t, r.URL.RawQuery, "ip=1.2.3.4")
			assert.Equal(t, r.Header.Get("X-Api-Key"), "ixu")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"duration":"3h59m55.756182786s","end_ip":16909060,"id":4,"origin":"cscli","scenario":"manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'","scope":"Ip","start_ip":16909060,"type":"ban","value":"1.2.3.4"}]`))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`null`))
			//no results
		}
	})
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		log.Fatalf("parsing api url: %s", apiURL)
	}

	//ok answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v1", "toto", auth.Client())
	if err != nil {
		log.Fatalf("new api client: %s", err.Error())
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
			EndIP:    16909060,
			ID:       4,
			Origin:   &torigin,
			Scenario: &tscenario,
			Scope:    &tscope,
			StartIP:  16909060,
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
		log.Fatalf("new api client: %s", err.Error())
	}
	if !reflect.DeepEqual(*decisions, *expected) {
		t.Fatalf("returned %+v, want %+v", resp, expected)
	}

	//Empty return
	decisionsFilter = DecisionsListOpts{IPEquals: new(string)}
	*decisionsFilter.IPEquals = "1.2.3.5"
	decisions, resp, err = newcli.Decisions.List(context.Background(), decisionsFilter)

	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}
	assert.Equal(t, len(*decisions), 0)

}

func TestDecisionsStream(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	_, mux, urlx, teardown := setup()
	defer teardown()

	mux.HandleFunc("/decisions/stream", func(w http.ResponseWriter, r *http.Request) {

		assert.Equal(t, r.Header.Get("X-Api-Key"), "ixu")
		testMethod(t, r, "GET")
		if r.Method == "GET" {

			if r.URL.RawQuery == "startup=true" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"deleted":null,"new":[{"duration":"3h59m55.756182786s","end_ip":16909060,"id":4,"origin":"cscli","scenario":"manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'","scope":"Ip","start_ip":16909060,"type":"ban","value":"1.2.3.4"}]}`))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"deleted":null,"new":null}`))
			}
		}
	})
	mux.HandleFunc("/decisions", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.Header.Get("X-Api-Key"), "ixu")
		testMethod(t, r, "DELETE")
		if r.Method == "DELETE" {
			w.WriteHeader(http.StatusOK)
		}
	})

	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		log.Fatalf("parsing api url: %s", apiURL)
	}

	//ok answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v1", "toto", auth.Client())
	if err != nil {
		log.Fatalf("new api client: %s", err.Error())
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
				EndIP:    16909060,
				ID:       4,
				Origin:   &torigin,
				Scenario: &tscenario,
				Scope:    &tscope,
				StartIP:  16909060,
				Type:     &ttype,
				Value:    &tvalue,
			},
		},
	}

	decisions, resp, err := newcli.Decisions.GetStream(context.Background(), true)

	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}

	if err != nil {
		log.Fatalf("new api client: %s", err.Error())
	}
	if !reflect.DeepEqual(*decisions, *expected) {
		t.Fatalf("returned %+v, want %+v", resp, expected)
	}

	//and second call, we get empty lists
	decisions, resp, err = newcli.Decisions.GetStream(context.Background(), false)

	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}
	assert.Equal(t, 0, len(decisions.New))
	assert.Equal(t, 0, len(decisions.Deleted))

	//delete stream
	resp, err = newcli.Decisions.StopStream(context.Background())

	if resp.Response.StatusCode != http.StatusOK {
		t.Errorf("Alerts.List returned status: %d, want %d", resp.Response.StatusCode, http.StatusOK)
	}
}
