package cticlient

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/go-cs-lib/pkg/ptr"
)

const validApiKey = "my-api-key"

// Copy pasted from actual API response
var smokeResponses = map[string]string{
	"1.1.1.1": `{"ip_range_score": 0, "ip": "1.1.1.1", "ip_range": "1.1.1.0/24", "as_name": "CLOUDFLARENET", "as_num": 13335, "location": {"country": null, "city": null, "latitude": null, "longitude": null}, "reverse_dns": "one.one.one.one", "behaviors": [{"name": "ssh:bruteforce", "label": "SSH Bruteforce", "description": "IP has been reported for performing brute force on ssh services."}, {"name": "tcp:scan", "label": "TCP Scan", "description": "IP has been reported for performing TCP port scanning."}, {"name": "http:scan", "label": "HTTP Scan", "description": "IP has been reported for performing actions related to HTTP vulnerability scanning and discovery."}], "history": {"first_seen": "2021-04-18T18:00:00+00:00", "last_seen": "2022-11-23T13:00:00+00:00", "full_age": 583, "days_age": 583}, "classifications": {"false_positives": [], "classifications": [{"name": "profile:insecure_services", "label": "Dangerous Services Exposed", "description": "IP exposes dangerous services (vnc, telnet, rdp), possibly due to a misconfiguration or because it's a honeypot."}, {"name": "profile:many_services", "label": "Many Services Exposed", "description": "IP exposes many open port, possibly due to a misconfiguration or because it's a honeypot."}]}, "attack_details": [{"name": "crowdsecurity/ssh-bf", "label": "SSH Bruteforce", "description": "Detect ssh brute force", "references": []}, {"name": "crowdsecurity/iptables-scan-multi_ports", "label": "Port Scanner", "description": "Detect tcp port scan", "references": []}, {"name": "crowdsecurity/ssh-slow-bf", "label": "Slow SSH Bruteforce", "description": "Detect slow ssh brute force", "references": []}, {"name": "crowdsecurity/http-probing", "label": "HTTP Scanner", "description": "Detect site scanning/probing from a single ip", "references": []}, {"name": "crowdsecurity/http-path-traversal-probing", "label": "Path Traversal Scanner", "description": "Detect path traversal attempt", "references": []}, {"name": "crowdsecurity/http-bad-user-agent", "label": "Known Bad User-Agent", "description": "Detect bad user-agents", "references": []}], "target_countries": {"DE": 33, "FR": 25, "US": 12, "CA": 8, "JP": 8, "AT": 4, "GB": 4, "AE": 4}, "background_noise_score": 4, "scores": {"overall": {"aggressiveness": 2, "threat": 2, "trust": 1, "anomaly": 2, "total": 2}, "last_day": {"aggressiveness": 0, "threat": 0, "trust": 0, "anomaly": 2, "total": 0}, "last_week": {"aggressiveness": 1, "threat": 2, "trust": 0, "anomaly": 2, "total": 1}, "last_month": {"aggressiveness": 3, "threat": 2, "trust": 0, "anomaly": 2, "total": 2}}, "references": []}`,
}

var fireResponses []string

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// wip
func fireHandler(req *http.Request) *http.Response {
	var err error
	apiKey := req.Header.Get("x-api-key")
	if apiKey != validApiKey {
		log.Warningf("invalid api key: %s", apiKey)
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       nil,
			Header:     make(http.Header),
		}
	}
	//unmarshal data
	if fireResponses == nil {
		page1, err := os.ReadFile("tests/fire-page1.json")
		if err != nil {
			panic("can't read file")
		}
		page2, err := os.ReadFile("tests/fire-page2.json")
		if err != nil {
			panic("can't read file")
		}
		fireResponses = []string{string(page1), string(page2)}
	}
	//let's assume we have two valid pages.
	page := 1
	if req.URL.Query().Get("page") != "" {
		page, err = strconv.Atoi(req.URL.Query().Get("page"))
		if err != nil {
			log.Warningf("no page ?!")
			return &http.Response{StatusCode: http.StatusInternalServerError}
		}
	}

	//how to react if you give a page number that is too big ?
	if page > len(fireResponses) {
		log.Warningf(" page too big %d vs %d", page, len(fireResponses))
		emptyResponse := `{
			"_links": {
			  "first": {
				"href": "https://cti.api.crowdsec.net/v1/fire/"
			  },
			  "self": {
				"href": "https://cti.api.crowdsec.net/v1/fire/?page=3&limit=3"
			  }
			},
			"items": []
		  }
		  `
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(emptyResponse))}
	}
	reader := io.NopCloser(strings.NewReader(fireResponses[page-1]))
	//we should care about limit too
	return &http.Response{
		StatusCode: http.StatusOK,
		// Send response to be tested
		Body:          reader,
		Header:        make(http.Header),
		ContentLength: 0,
	}
}

func smokeHandler(req *http.Request) *http.Response {
	apiKey := req.Header.Get("x-api-key")
	if apiKey != validApiKey {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       nil,
			Header:     make(http.Header),
		}
	}

	requestedIP := strings.Split(req.URL.Path, "/")[3]
	response, ok := smokeResponses[requestedIP]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(`{"message": "IP address information not found"}`)),
			Header:     make(http.Header),
		}
	}

	reader := io.NopCloser(strings.NewReader(response))

	return &http.Response{
		StatusCode: http.StatusOK,
		// Send response to be tested
		Body:          reader,
		Header:        make(http.Header),
		ContentLength: 0,
	}
}

func rateLimitedHandler(req *http.Request) *http.Response {
	apiKey := req.Header.Get("x-api-key")
	if apiKey != validApiKey {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       nil,
			Header:     make(http.Header),
		}
	}
	return &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Body:       nil,
		Header:     make(http.Header),
	}
}

func searchHandler(req *http.Request) *http.Response {
	apiKey := req.Header.Get("x-api-key")
	if apiKey != validApiKey {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       nil,
			Header:     make(http.Header),
		}
	}
	url, _ := url.Parse(req.URL.String())
	ipsParam := url.Query().Get("ips")
	if ipsParam == "" {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       nil,
			Header:     make(http.Header),
		}
	}

	totalIps := 0
	notFound := 0
	ips := strings.Split(ipsParam, ",")
	for _, ip := range ips {
		_, ok := smokeResponses[ip]
		if ok {
			totalIps++
		} else {
			notFound++
		}
	}
	response := fmt.Sprintf(`{"total": %d, "not_found": %d, "items": [`, totalIps, notFound)
	for _, ip := range ips {
		response += smokeResponses[ip]
	}
	response += "]}"
	reader := io.NopCloser(strings.NewReader(response))
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       reader,
		Header:     make(http.Header),
	}
}

func TestBadFireAuth(t *testing.T) {
	ctiClient := NewCrowdsecCTIClient(WithAPIKey("asdasd"), WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(fireHandler),
	}))
	_, err := ctiClient.Fire(FireParams{})
	assert.EqualError(t, err, ErrUnauthorized.Error())
}

func TestFireOk(t *testing.T) {
	cticlient := NewCrowdsecCTIClient(WithAPIKey(validApiKey), WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(fireHandler),
	}))
	data, err := cticlient.Fire(FireParams{})
	assert.Equal(t, err, nil)
	assert.Equal(t, len(data.Items), 3)
	assert.Equal(t, data.Items[0].Ip, "1.2.3.4")
	//page 1 is the default
	data, err = cticlient.Fire(FireParams{Page: ptr.Of(1)})
	assert.Equal(t, err, nil)
	assert.Equal(t, len(data.Items), 3)
	assert.Equal(t, data.Items[0].Ip, "1.2.3.4")
	//page 2
	data, err = cticlient.Fire(FireParams{Page: ptr.Of(2)})
	assert.Equal(t, err, nil)
	assert.Equal(t, len(data.Items), 3)
	assert.Equal(t, data.Items[0].Ip, "4.2.3.4")
}

func TestFirePaginator(t *testing.T) {
	cticlient := NewCrowdsecCTIClient(WithAPIKey(validApiKey), WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(fireHandler),
	}))
	paginator := NewFirePaginator(cticlient, FireParams{})
	items, err := paginator.Next()
	assert.Equal(t, err, nil)
	assert.Equal(t, len(items), 3)
	assert.Equal(t, items[0].Ip, "1.2.3.4")
	items, err = paginator.Next()
	assert.Equal(t, err, nil)
	assert.Equal(t, len(items), 3)
	assert.Equal(t, items[0].Ip, "4.2.3.4")
	items, err = paginator.Next()
	assert.Equal(t, err, nil)
	assert.Equal(t, len(items), 0)

}

func TestBadSmokeAuth(t *testing.T) {
	ctiClient := NewCrowdsecCTIClient(WithAPIKey("asdasd"), WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(smokeHandler),
	}))
	_, err := ctiClient.GetIPInfo("1.1.1.1")
	assert.EqualError(t, err, ErrUnauthorized.Error())
}

func TestSmokeInfoValidIP(t *testing.T) {
	ctiClient := NewCrowdsecCTIClient(WithAPIKey(validApiKey), WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(smokeHandler),
	}))
	resp, err := ctiClient.GetIPInfo("1.1.1.1")
	if err != nil {
		t.Fatalf("failed to get ip info: %s", err)
	}

	assert.Equal(t, "1.1.1.1", resp.Ip)
	assert.Equal(t, ptr.Of("1.1.1.0/24"), resp.IpRange)
}

func TestSmokeUnknownIP(t *testing.T) {
	ctiClient := NewCrowdsecCTIClient(WithAPIKey(validApiKey), WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(smokeHandler),
	}))
	resp, err := ctiClient.GetIPInfo("42.42.42.42")
	if err != nil {
		t.Fatalf("failed to get ip info: %s", err)
	}

	assert.Equal(t, "", resp.Ip)
}

func TestRateLimit(t *testing.T) {
	ctiClient := NewCrowdsecCTIClient(WithAPIKey(validApiKey), WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(rateLimitedHandler),
	}))
	_, err := ctiClient.GetIPInfo("1.1.1.1")
	assert.EqualError(t, err, ErrLimit.Error())
}

func TestSearchIPs(t *testing.T) {
	ctiClient := NewCrowdsecCTIClient(WithAPIKey(validApiKey), WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(searchHandler),
	}))
	resp, err := ctiClient.SearchIPs([]string{"1.1.1.1", "42.42.42.42"})
	if err != nil {
		t.Fatalf("failed to search ips: %s", err)
	}
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, 1, resp.NotFound)
	assert.Equal(t, 1, len(resp.Items))
	assert.Equal(t, "1.1.1.1", resp.Items[0].Ip)
}

//TODO: fire tests + pagination

func TestFireInit(t *testing.T) {

}
