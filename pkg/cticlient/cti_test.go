package cticlient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

var sampledata = map[string]CTIResponse{
	//1.2.3.4 is a known false positive
	"1.2.3.4": CTIResponse{},
	//1.2.3.5 is a known bad-guy, and part of FIRE
	"1.2.3.5": CTIResponse{},
	//1.2.3.6 is a bad guy (high bg noise), but not in FIRE
	"1.2.3.6": CTIResponse{},
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
		if len(frags) != 2 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"message":"Bad Request"}`))
			return
		}

		ip := frags[1]

		if ip == "" {
			panic("empty ip")
			// {
			// 	"message": "Please provide a search string (example: ips=a,b,c,d)"
			//   }

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

func TestCTIAuth(t *testing.T) {

	_, urlx, teardown := setup()
	apiURL, err := url.Parse(urlx + "/")
	if err != nil {
		t.Fatalf("parsing api url: %s", apiURL)
	}

	defer teardown()
	CTIUrl = urlx
	key := "BAD_KEY"
	if err := InitCTI(&key, nil, nil); err != nil {
		t.Fatalf("InitCTI failed: %s", err)
	}
	ret := IpCTI("1.2.3.4")
	fmt.Printf("ret: %s", spew.Sdump(ret))

}
