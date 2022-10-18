package apiclient

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestWatcherAuth(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	defer teardown()
	//body: models.WatcherRegistrationRequest{MachineID: &config.MachineID, Password: &config.Password}

	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		newStr := buf.String()
		log.Printf("--> %s", newStr)
		if newStr == `{"machine_id":"test_login","password":"test_password","scenarios":["crowdsecurity/test"]}
` {
			log.Printf("ok cool")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"code":200,"expire":"2029-11-30T14:14:24+01:00","token":"toto"}`)
		} else {
			w.WriteHeader(http.StatusForbidden)
			log.Printf("badbad")
			fmt.Fprintf(w, `{"message":"access forbidden"}`)
		}
	})
	log.Printf("URL is %s", urlx)
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	//ok auth
	mycfg := &Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		URL:           apiURL,
		VersionPrefix: "v1",
		Scenarios:     []string{"crowdsecurity/test"},
	}
	client, err := NewClient(mycfg)

	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	_, err = client.Auth.AuthenticateWatcher(context.Background(), models.WatcherAuthRequest{
		MachineID: &mycfg.MachineID,
		Password:  &mycfg.Password,
		Scenarios: mycfg.Scenarios,
	})
	if err != nil {
		t.Fatalf("unexpect auth err 0: %s", err)
	}

	//bad auth
	mycfg = &Config{
		MachineID:     "BADtest_login",
		Password:      "BADtest_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		URL:           apiURL,
		VersionPrefix: "v1",
		Scenarios:     []string{"crowdsecurity/test"},
	}
	client, err = NewClient(mycfg)

	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	_, err = client.Auth.AuthenticateWatcher(context.Background(), models.WatcherAuthRequest{
		MachineID: &mycfg.MachineID,
		Password:  &mycfg.Password,
	})
	assert.Contains(t, err.Error(), "API error: access forbidden")

}

func TestWatcherRegister(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	defer teardown()
	//body: models.WatcherRegistrationRequest{MachineID: &config.MachineID, Password: &config.Password}

	mux.HandleFunc("/watchers", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		newStr := buf.String()
		assert.Equal(t, newStr, `{"machine_id":"test_login","password":"test_password"}
`)
		w.WriteHeader(http.StatusOK)
	})
	log.Printf("URL is %s", urlx)
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}
	client, err := RegisterClient(&Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		URL:           apiURL,
		VersionPrefix: "v1",
	}, &http.Client{})
	if err != nil {
		t.Fatalf("while registering client : %s", err)
	}
	log.Printf("->%T", client)
}

func TestWatcherUnregister(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	defer teardown()
	//body: models.WatcherRegistrationRequest{MachineID: &config.MachineID, Password: &config.Password}

	mux.HandleFunc("/watchers", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "DELETE")
		assert.Equal(t, r.ContentLength, int64(0))
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		newStr := buf.String()
		if newStr == `{"machine_id":"test_login","password":"test_password","scenarios":["crowdsecurity/test"]}
` {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"code":200,"expire":"2029-11-30T14:14:24+01:00","token":"toto"}`)
		} else {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"message":"access forbidden"}`)
		}
	})

	log.Printf("URL is %s", urlx)
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}
	mycfg := &Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		URL:           apiURL,
		VersionPrefix: "v1",
		Scenarios:     []string{"crowdsecurity/test"},
	}
	client, err := NewClient(mycfg)

	if err != nil {
		t.Fatalf("new api client: %s", err)
	}
	_, err = client.Auth.UnregisterWatcher(context.Background())
	if err != nil {
		t.Fatalf("while registering client : %s", err)
	}
	log.Printf("->%T", client)
}

func TestWatcherEnroll(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	mux, urlx, teardown := setup()
	defer teardown()

	mux.HandleFunc("/watchers/enroll", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		newStr := buf.String()
		log.Debugf("body -> %s", newStr)
		if newStr == `{"attachment_key":"goodkey","name":"","tags":[],"overwrite":false}
` {
			log.Print("good key")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"statusCode": 200, "message": "OK"}`)
		} else {
			log.Print("bad key")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"message":"the attachment key provided is not valid"}`)
		}
	})
	mux.HandleFunc("/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"code":200,"expire":"2029-11-30T14:14:24+01:00","token":"toto"}`)
	})
	log.Printf("URL is %s", urlx)
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	mycfg := &Config{
		MachineID:     "test_login",
		Password:      "test_password",
		UserAgent:     fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		URL:           apiURL,
		VersionPrefix: "v1",
		Scenarios:     []string{"crowdsecurity/test"},
	}
	client, err := NewClient(mycfg)

	if err != nil {
		t.Fatalf("new api client: %s", err)
	}

	_, err = client.Auth.EnrollWatcher(context.Background(), "goodkey", "", []string{}, false)
	if err != nil {
		t.Fatalf("unexpect enroll err: %s", err)
	}

	_, err = client.Auth.EnrollWatcher(context.Background(), "badkey", "", []string{}, false)
	assert.Contains(t, err.Error(), "the attachment key provided is not valid")
}
