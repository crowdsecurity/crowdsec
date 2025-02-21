package apiclient

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/modelscapi"
)

func TestDecisionsList(t *testing.T) {
	ctx := t.Context()
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	defer teardown()

	mux.HandleFunc("/decisions", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")

		if r.URL.RawQuery == "ip=1.2.3.4" {
			assert.Equal(t, "ip=1.2.3.4", r.URL.RawQuery)
			assert.Equal(t, "ixu", r.Header.Get("X-Api-Key"))
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`[{"duration":"3h59m55.756182786s","id":4,"origin":"cscli","scenario":"manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'","scope":"Ip","type":"ban","value":"1.2.3.4"}]`))
			assert.NoError(t, err)
		} else {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`null`))
			assert.NoError(t, err)
		}
	})

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	// ok answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v1", "toto", auth.Client())
	require.NoError(t, err)

	expected := &models.GetDecisionsResponse{
		&models.Decision{
			Duration: ptr.Of("3h59m55.756182786s"),
			ID:       4,
			Origin:   ptr.Of("cscli"),
			Scenario: ptr.Of("manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'"),
			Scope:    ptr.Of("Ip"),
			Type:     ptr.Of("ban"),
			Value:    ptr.Of("1.2.3.4"),
		},
	}

	// OK decisions
	decisionsFilter := DecisionsListOpts{IPEquals: ptr.Of("1.2.3.4")}
	decisions, resp, err := newcli.Decisions.List(ctx, decisionsFilter)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)
	assert.Equal(t, *expected, *decisions)

	// Empty return
	decisionsFilter = DecisionsListOpts{IPEquals: ptr.Of("1.2.3.5")}
	decisions, resp, err = newcli.Decisions.List(ctx, decisionsFilter)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)
	assert.Empty(t, *decisions)
}

func TestDecisionsStream(t *testing.T) {
	ctx := t.Context()
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	defer teardown()

	mux.HandleFunc("/decisions/stream", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "ixu", r.Header.Get("X-Api-Key"))
		testMethod(t, r, http.MethodGet)

		if r.Method == http.MethodGet {
			if strings.Contains(r.URL.RawQuery, "startup=true") {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{"deleted":null,"new":[{"duration":"3h59m55.756182786s","id":4,"origin":"cscli","scenario":"manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'","scope":"Ip","type":"ban","value":"1.2.3.4"}]}`))
				assert.NoError(t, err)
			} else {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{"deleted":null,"new":null}`))
				assert.NoError(t, err)
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
	require.NoError(t, err)

	// ok answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v1", "toto", auth.Client())
	require.NoError(t, err)

	expected := &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			&models.Decision{
				Duration: ptr.Of("3h59m55.756182786s"),
				ID:       4,
				Origin:   ptr.Of("cscli"),
				Scenario: ptr.Of("manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'"),
				Scope:    ptr.Of("Ip"),
				Type:     ptr.Of("ban"),
				Value:    ptr.Of("1.2.3.4"),
			},
		},
	}

	decisions, resp, err := newcli.Decisions.GetStream(ctx, DecisionsStreamOpts{Startup: true})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)
	assert.Equal(t, *expected, *decisions)

	// and second call, we get empty lists
	decisions, resp, err = newcli.Decisions.GetStream(ctx, DecisionsStreamOpts{Startup: false})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)
	assert.Empty(t, decisions.New)
	assert.Empty(t, decisions.Deleted)

	// delete stream
	resp, err = newcli.Decisions.StopStream(ctx)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)
}

func TestDecisionsStreamV3Compatibility(t *testing.T) {
	ctx := t.Context()
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setupWithPrefix("v3")
	defer teardown()

	mux.HandleFunc("/decisions/stream", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "ixu", r.Header.Get("X-Api-Key"))
		testMethod(t, r, http.MethodGet)

		if r.Method == http.MethodGet {
			if strings.Contains(r.URL.RawQuery, "startup=true") {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{"deleted":[{"scope":"ip","decisions":["1.2.3.5"]}],"new":[{"scope":"ip", "scenario": "manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'", "decisions":[{"duration":"3h59m55.756182786s","value":"1.2.3.4"}]}]}`))
				assert.NoError(t, err)
			} else {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{"deleted":null,"new":null}`))
				assert.NoError(t, err)
			}
		}
	})

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	// ok answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v3", "toto", auth.Client())
	require.NoError(t, err)

	torigin := "CAPI"
	tscope := "ip"
	ttype := "ban"
	expected := &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			&models.Decision{
				Duration: ptr.Of("3h59m55.756182786s"),
				Origin:   &torigin,
				Scenario: ptr.Of("manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'"),
				Scope:    &tscope,
				Type:     &ttype,
				Value:    ptr.Of("1.2.3.4"),
			},
		},
		Deleted: models.GetDecisionsResponse{
			&models.Decision{
				Duration: ptr.Of("1h"),
				Origin:   &torigin,
				Scenario: ptr.Of("deleted"),
				Scope:    &tscope,
				Type:     &ttype,
				Value:    ptr.Of("1.2.3.5"),
			},
		},
	}

	// GetStream is supposed to consume v3 payload and return v2 response
	decisions, resp, err := newcli.Decisions.GetStream(ctx, DecisionsStreamOpts{Startup: true})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)
	assert.Equal(t, *expected, *decisions)
}

func TestDecisionsStreamV3(t *testing.T) {
	ctx := t.Context()
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setupWithPrefix("v3")
	defer teardown()

	mux.HandleFunc("/decisions/stream", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "ixu", r.Header.Get("X-Api-Key"))
		testMethod(t, r, http.MethodGet)

		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`{"deleted":[{"scope":"ip","decisions":["1.2.3.5"]}],
			"new":[{"scope":"ip", "scenario": "manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'", "decisions":[{"duration":"3h59m55.756182786s","value":"1.2.3.4"}]}],
			"links": {"blocklists":[{"name":"blocklist1","url":"/v3/blocklist","scope":"ip","remediation":"ban","duration":"24h"}]}}`))
			assert.NoError(t, err)
		}
	})

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	// ok answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v3", "toto", auth.Client())
	require.NoError(t, err)

	tscope := "ip"
	expected := &modelscapi.GetDecisionsStreamResponse{
		New: modelscapi.GetDecisionsStreamResponseNew{
			&modelscapi.GetDecisionsStreamResponseNewItem{
				Decisions: []*modelscapi.GetDecisionsStreamResponseNewItemDecisionsItems0{
					{
						Duration: ptr.Of("3h59m55.756182786s"),
						Value:    ptr.Of("1.2.3.4"),
					},
				},
				Scenario: ptr.Of("manual 'ban' from '82929df7ee394b73b81252fe3b4e50203yaT2u6nXiaN7Ix9'"),
				Scope:    &tscope,
			},
		},
		Deleted: modelscapi.GetDecisionsStreamResponseDeleted{
			&modelscapi.GetDecisionsStreamResponseDeletedItem{
				Scope: &tscope,
				Decisions: []string{
					"1.2.3.5",
				},
			},
		},
		Links: &modelscapi.GetDecisionsStreamResponseLinks{
			Blocklists: []*modelscapi.BlocklistLink{
				{
					Duration:    ptr.Of("24h"),
					Name:        ptr.Of("blocklist1"),
					Remediation: ptr.Of("ban"),
					Scope:       ptr.Of("ip"),
					URL:         ptr.Of("/v3/blocklist"),
				},
			},
		},
	}

	// GetStream is supposed to consume v3 payload and return v2 response
	decisions, resp, err := newcli.Decisions.GetStreamV3(ctx, DecisionsStreamOpts{Startup: true})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.Response.StatusCode)
	assert.Equal(t, *expected, *decisions)
}

func TestDecisionsFromBlocklist(t *testing.T) {
	ctx := t.Context()
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
			_, err := w.Write([]byte("1.2.3.4\r\n1.2.3.5"))
			assert.NoError(t, err)
		}
	})

	apiURL, err := url.Parse(urlx + "/")
	require.NoError(t, err)

	// ok answer
	auth := &APIKeyTransport{
		APIKey: "ixu",
	}

	newcli, err := NewDefaultClient(apiURL, "v3", "toto", auth.Client())
	require.NoError(t, err)

	tdurationBlocklist := "24h"
	tnameBlocklist := "blocklist1"
	tremediationBlocklist := "ban"
	tscopeBlocklist := "ip"
	turlBlocklist := urlx + "/v3/blocklist"
	torigin := "lists"
	expected := []*models.Decision{
		{
			Duration: &tdurationBlocklist,
			Value:    ptr.Of("1.2.3.4"),
			Scenario: &tnameBlocklist,
			Scope:    &tscopeBlocklist,
			Type:     &tremediationBlocklist,
			Origin:   &torigin,
		},
		{
			Duration: &tdurationBlocklist,
			Value:    ptr.Of("1.2.3.5"),
			Scenario: &tnameBlocklist,
			Scope:    &tscopeBlocklist,
			Type:     &tremediationBlocklist,
			Origin:   &torigin,
		},
	}
	decisions, isModified, err := newcli.Decisions.GetDecisionsFromBlocklist(ctx, &modelscapi.BlocklistLink{
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

	assert.Equal(t, expected, decisions)

	// test cache control
	_, isModified, err = newcli.Decisions.GetDecisionsFromBlocklist(ctx, &modelscapi.BlocklistLink{
		URL:         &turlBlocklist,
		Scope:       &tscopeBlocklist,
		Remediation: &tremediationBlocklist,
		Name:        &tnameBlocklist,
		Duration:    &tdurationBlocklist,
	}, ptr.Of("Sun, 01 Jan 2023 01:01:01 GMT"))

	require.NoError(t, err)
	assert.False(t, isModified)

	_, isModified, err = newcli.Decisions.GetDecisionsFromBlocklist(ctx, &modelscapi.BlocklistLink{
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
	ctx := t.Context()

	mux, urlx, teardown := setup()
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"code": 200, "expire": "2030-01-02T15:04:05Z", "token": "oklol"}`))
		assert.NoError(t, err)
	})

	mux.HandleFunc("/decisions", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "DELETE")
		assert.Equal(t, "ip=1.2.3.4", r.URL.RawQuery)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"nbDeleted":"1"}`))
		assert.NoError(t, err)
		// w.Write([]byte(`{"message":"0 deleted alerts"}`))
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

	filters := DecisionsDeleteOpts{IPEquals: new(string)}
	*filters.IPEquals = "1.2.3.4"

	deleted, _, err := client.Decisions.Delete(ctx, filters)
	require.NoError(t, err)
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
		CommunityPull          bool
		AdditionalPull         bool
	}

	tests := []struct {
		name        string
		fields      fields
		expected    string
		expectedErr string
	}{
		{
			name:     "no filter",
			expected: baseURLString + "?",
			fields: fields{
				CommunityPull:  true,
				AdditionalPull: true,
			},
		},
		{
			name: "startup=true",
			fields: fields{
				Startup:        true,
				CommunityPull:  true,
				AdditionalPull: true,
			},
			expected: baseURLString + "?startup=true",
		},
		{
			name: "set all params",
			fields: fields{
				Startup:                true,
				Scopes:                 "ip,range",
				ScenariosContaining:    "ssh",
				ScenariosNotContaining: "bf",
				CommunityPull:          true,
				AdditionalPull:         true,
			},
			expected: baseURLString + "?scenarios_containing=ssh&scenarios_not_containing=bf&scopes=ip%2Crange&startup=true",
		},
		{
			name: "pull options",
			fields: fields{
				CommunityPull:  false,
				AdditionalPull: false,
			},
			expected: baseURLString + "?additional_pull=false&community_pull=false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &DecisionsStreamOpts{
				Startup:                tt.fields.Startup,
				Scopes:                 tt.fields.Scopes,
				ScenariosContaining:    tt.fields.ScenariosContaining,
				ScenariosNotContaining: tt.fields.ScenariosNotContaining,
				CommunityPull:          tt.fields.CommunityPull,
				AdditionalPull:         tt.fields.AdditionalPull,
			}

			got, err := o.addQueryParamsToURL(baseURLString)
			cstest.RequireErrorContains(t, err, tt.expectedErr)

			if tt.expectedErr != "" {
				return
			}

			gotURL, err := url.Parse(got)
			require.NoError(t, err)

			expectedURL, err := url.Parse(tt.expected)
			require.NoError(t, err)

			assert.Equal(t, *expectedURL, *gotURL)
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
