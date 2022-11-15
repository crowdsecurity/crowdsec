package cticlient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var sampledata = map[string]CTIResponse{
	//1.2.3.4 is a known false positive
	"1.2.3.4": {
		Ip: "1.2.3.4",
		Classifications: CTIClassifications{
			FalsePositives: []CTIClassification{
				{
					Name:  "example_false_positive",
					Label: "Example False Positive",
				},
			},
		},
	},
	//1.2.3.5 is a known bad-guy, and part of FIRE
	"1.2.3.5": {
		Ip: "1.2.3.5",
		Classifications: CTIClassifications{
			Classifications: []CTIClassification{
				{
					Name:        "community-blocklist",
					Label:       "CrowdSec Community Blocklist",
					Description: "IP belong to the CrowdSec Community Blocklist",
				},
			},
		},
	},
	//1.2.3.6 is a bad guy (high bg noise), but not in FIRE
	"1.2.3.6": {
		Ip:                   "1.2.3.6",
		BackgroundNoiseScore: new(int),
		Behaviours: []*CTIBehaviour{
			{Name: "ssh:bruteforce", Label: "SSH Bruteforce", Description: "SSH Bruteforce"},
		},
		AttackDetails: []*CTIAttackDetails{
			{Name: "crowdsecurity/ssh-bf", Label: "Example Attack"},
			{Name: "crowdsecurity/ssh-slow-bf", Label: "Example Attack"},
		},
	},
	//1.2.3.7 is a ok guy, but part of a bad range
	"1.2.3.7": CTIResponse{},
}

func EmptyCTIResponse(ip string) CTIResponse {
	return CTIResponse{
		IpRangeScore: 0,
		Ip:           ip,
		Location:     CTILocationInfo{},
	}
}

/*
TBD : Simulate correctly quotas exhaustion
*/
func setup() (Router *http.ServeMux, serverURL string, teardown func()) {

	//set static values
	*sampledata["1.2.3.6"].BackgroundNoiseScore = 10

	// mux is the HTTP request multiplexer used with the test server.
	Router = http.NewServeMux()
	baseURLPath := "/v2"

	apiHandler := http.NewServeMux()
	apiHandler.Handle(baseURLPath+"/", http.StripPrefix(baseURLPath, Router))

	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(apiHandler)

	// let's mock the API endpoints
	Router.HandleFunc("/smoke/", func(w http.ResponseWriter, r *http.Request) {
		//testMethod(t, r, "GET")
		if r.Header.Get("X-Api-Key") != "EXAMPLE_API_KEY" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message":"Forbidden"}`))
			return
		}

		frags := strings.Split(r.RequestURI, "/")
		//[empty] [smoke] [v2] [actual_ip]
		if len(frags) != 4 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"message":"Bad Request"}`))
			return
		}
		ip := frags[3]

		if ip == "" {
			//to be fixed to stick w/ real behaviour
			panic("empty ip")

		}
		// vars := mux.Vars(r)
		if v, ok := sampledata[ip]; ok {
			data, err := json.Marshal(v)
			if err != nil {
				panic("unable to marshal")
			}
			w.WriteHeader(http.StatusOK)
			w.Write(data)
			return
		}
		w.WriteHeader(http.StatusOK)
		data, err := json.Marshal(EmptyCTIResponse(ip))
		if err != nil {
			panic("unable to marshal")
		}
		w.Write(data)
		return
	})
	return Router, server.URL, server.Close
}

func TestCTIAuthKO(t *testing.T) {

	_, urlx, teardown := setup()
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	defer teardown()
	defer ShutdownCTI()
	CTIUrl = urlx
	key := "BAD_KEY"
	if err := InitCTI(&key, nil, nil); err != nil {
		t.Fatalf("InitCTI failed: %s", err)
	}

	ret := IpCTI("1.2.3.4")
	assert.Equal(t, false, ret.Ok(), "should be ko")
	assert.Equal(t, CTIResponse{}, ret, "auth failed, empty answer")
	assert.Equal(t, CTIApiEnabled, false, "auth failed, api disabled")
	//auth is disabled, we should always receive empty object
	ret = IpCTI("1.2.3.4")
	assert.Equal(t, false, ret.Ok(), "should be ko")
	assert.Equal(t, CTIResponse{}, ret, "auth failed, empty answer")
}

func TestCTINoKey(t *testing.T) {

	_, urlx, teardown := setup()
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	defer teardown()
	defer ShutdownCTI()
	CTIUrl = urlx
	//key := ""
	err = InitCTI(nil, nil, nil)
	assert.NotEqual(t, err, nil, "InitCTI should fail")
	ret := IpCTI("1.2.3.4")
	assert.Equal(t, false, ret.Ok(), "should be ko")
	assert.Equal(t, CTIResponse{}, ret, "auth failed, empty answer")
	assert.Equal(t, CTIApiEnabled, false, "auth failed, api disabled")
}

func TestCTIAuthOK(t *testing.T) {

	_, urlx, teardown := setup()
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	defer teardown()
	defer ShutdownCTI()

	CTIUrl = urlx
	key := "EXAMPLE_API_KEY"
	if err := InitCTI(&key, nil, nil); err != nil {
		t.Fatalf("InitCTI failed: %s", err)
	}

	ret := IpCTI("1.2.3.4")
	assert.Equal(t, true, ret.Ok(), "should be ok")
	assert.Equal(t, "1.2.3.4", ret.Ip, "auth failed, empty answer")
	assert.Equal(t, CTIApiEnabled, true, "auth failed, api disabled")
}
func TestCTIKnownFP(t *testing.T) {
	_, urlx, teardown := setup()
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	defer teardown()
	defer ShutdownCTI()

	CTIUrl = urlx
	key := "EXAMPLE_API_KEY"
	if err := InitCTI(&key, nil, nil); err != nil {
		t.Fatalf("InitCTI failed: %s", err)
	}

	ret := IpCTI("1.2.3.4")
	assert.Equal(t, true, ret.Ok(), "should be ok")
	assert.Equal(t, "1.2.3.4", ret.Ip, "auth failed, empty answer")
	assert.Equal(t, ret.IsFalsePositive(), true, "1.2.3.4 is a known false positive")
}

func TestCTIBelongsToFire(t *testing.T) {
	_, urlx, teardown := setup()
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	defer teardown()
	defer ShutdownCTI()

	CTIUrl = urlx
	key := "EXAMPLE_API_KEY"
	if err := InitCTI(&key, nil, nil); err != nil {
		t.Fatalf("InitCTI failed: %s", err)
	}

	ret := IpCTI("1.2.3.5")
	assert.Equal(t, true, ret.Ok(), "should be ok")
	assert.Equal(t, "1.2.3.5", ret.Ip, "auth failed, empty answer")
	assert.Equal(t, ret.IsPartOfCommunityBlocklist(), true, "1.2.3.5 is a known false positive")
}

func TestCTIBehaviours(t *testing.T) {
	_, urlx, teardown := setup()
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	defer teardown()
	defer ShutdownCTI()

	CTIUrl = urlx
	key := "EXAMPLE_API_KEY"
	if err := InitCTI(&key, nil, nil); err != nil {
		t.Fatalf("InitCTI failed: %s", err)
	}

	ret := IpCTI("1.2.3.6")
	assert.Equal(t, true, ret.Ok(), "should be ok")
	assert.Equal(t, ret.Ip, "1.2.3.6", "auth failed, empty answer")
	//ssh:bruteforce
	assert.Equal(t, []string{"ssh:bruteforce"}, ret.GetBehaviours(), "error matching behaviours")
	assert.Equal(t, []string{"crowdsecurity/ssh-bf", "crowdsecurity/ssh-slow-bf"}, ret.GetAttackDetails(), "error matching behaviours")
	assert.Equal(t, 10, ret.GetBackgroundNoiseScore(), "error matching bg noise")
}

func TestCacheFetch(t *testing.T) {
	_, urlx, teardown := setup()
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	defer teardown()
	defer ShutdownCTI()

	CTIUrl = urlx
	key := "EXAMPLE_API_KEY"
	ttl := 1 * time.Second
	if err := InitCTI(&key, &ttl, nil); err != nil {
		t.Fatalf("InitCTI failed: %s", err)
	}

	ret := IpCTI("1.2.3.6")
	assert.Equal(t, true, ret.Ok(), "should be ok")
	assert.Equal(t, "1.2.3.6", ret.Ip, "initial fetch : bad item")
	assert.Equal(t, 1, CTICache.Len(true), "initial fetch : bad cache size")
	assert.Equal(t, "1.2.3.6", CTICache.Keys(true)[0].(string), "initial fetch : bad cache keys")
	//get it a second time before it expires
	ret = IpCTI("1.2.3.6")
	assert.Equal(t, true, ret.Ok(), "should be ok")
	assert.Equal(t, "1.2.3.6", ret.Ip, "initial fetch : bad item")
	assert.Equal(t, 1, CTICache.Len(true), "initial fetch : bad cache size")
	assert.Equal(t, "1.2.3.6", CTICache.Keys(true)[0].(string), "initial fetch : bad cache keys")
	//let data expire
	time.Sleep(1 * time.Second)
	assert.Equal(t, 0, CTICache.Len(true), "after ttl : bad cache size")
	//fetch again
	ret = IpCTI("1.2.3.6")
	assert.Equal(t, true, ret.Ok(), "should be ok")
	assert.Equal(t, "1.2.3.6", ret.Ip, "second fetch : bad item")
	assert.Equal(t, 1, CTICache.Len(true), "second fetch : bad cache size")
	assert.Equal(t, "1.2.3.6", CTICache.Keys(true)[0].(string), "initial fetch : bad cache keys")
}

//GetMaliciousnessScore
