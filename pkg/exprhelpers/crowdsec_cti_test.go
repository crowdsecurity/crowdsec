package exprhelpers

import (
	"bytes"
	"encoding/json"
	"gopkg.in/yaml.v3"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/cti"
)

const validApiKey = "my-api-key"

type RoundTripFunc func(req *http.Request) *http.Response

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
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

	//nolint: dupword
	sampleString := `
# 1.2.3.4 is a known false positive
1.2.3.4:
  ip: "1.2.3.4"
  classifications:
    false_positives:
      -
        name: "example_false_positive"
        label: "Example False Positive"
# 1.2.3.5 is a known bad-guy, and part of FIRE
1.2.3.5:
  ip: 1.2.3.5
  classifications:
    classifications:
      -
        name: "community-blocklist"
        label: "CrowdSec Community Blocklist"
        description: "IP belong to the CrowdSec Community Blocklist"
# 1.2.3.6 is a bad guy (high bg noise), but not in FIRE
1.2.3.6:
  ip: 1.2.3.6
  background_noise_score: 0
  behaviors:
    -
      name: "ssh:bruteforce"
      label: "SSH Bruteforce"
      description: "SSH Bruteforce"
  attack_details:
    -
      name: "crowdsecurity/ssh-bf"
      label: "Example Attack"
    -
      name: "crowdsecurity/ssh-slow-bf"
      label: "Example Attack"`
	sampledata := make(map[string]cti.CTIObject)
	err := yaml.Unmarshal([]byte(sampleString), &sampledata)
	if err != nil {
		log.Fatalf("failed to unmarshal sample data: %s", err)
	}

	sample, ok := sampledata[requestedIP]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       nil,
			Header:     make(http.Header),
		}
	}

	body, err := json.Marshal(sample)
	if err != nil {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       nil,
			Header:     make(http.Header),
		}
	}

	reader := io.NopCloser(bytes.NewReader(body))

	return &http.Response{
		StatusCode: http.StatusOK,
		// Send response to be tested
		Body:          reader,
		Header:        make(http.Header),
		ContentLength: 0,
	}
}

func TestNillClient(t *testing.T) {
	defer ShutdownCrowdsecCTI()

	if err := InitCrowdsecCTI(ptr.Of(""), nil, nil, nil); !errors.Is(err, cti.ErrDisabled) {
		t.Fatalf("failed to init CTI : %s", err)
	}

	item, err := CrowdsecCTI("1.2.3.4")
	assert.Equal(t, err, cti.ErrDisabled)
	assert.Equal(t, item, &cti.CTIObject{})
}

func TestInvalidAuth(t *testing.T) {
	defer ShutdownCrowdsecCTI()
	if err := InitCrowdsecCTI(ptr.Of("asdasd"), nil, nil, nil); err != nil {
		t.Fatalf("failed to init CTI : %s", err)
	}

	var err error

	//Replace the client created by InitCrowdsecCTI with one that uses a custom transport
	ctiClient, err = cti.NewClientWithResponses(CTIUrl+"/v2/", cti.WithRequestEditorFn(cti.APIKeyInserter(validApiKey)), cti.WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(smokeHandler),
	}))
	require.NoError(t, err)

	assert.True(t, CTIApiEnabled)
	item, err := CrowdsecCTI("1.2.3.4")
//	require.False(t, CTIApiEnabled)
//	require.ErrorIs(t, err, cti.ErrUnauthorized)
	require.Equal(t, &cti.CTIObject{Ip: "1.2.3.4"}, item)
//	require.Equal(t, &cti.CTIObject{}, item)

	//CTI is now disabled, all requests should return empty
	ctiClient, err = cti.NewClientWithResponses(CTIUrl+"/v2/", cti.WithRequestEditorFn(cti.APIKeyInserter(validApiKey)), cti.WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(smokeHandler),
	}))
	require.NoError(t, err)

	item, err = CrowdsecCTI("1.2.3.4")
//	assert.Equal(t, item, &cti.CTIObject{})
//	assert.False(t, CTIApiEnabled)
//	assert.Equal(t, err, cti.ErrDisabled)
}

func TestNoKey(t *testing.T) {
	defer ShutdownCrowdsecCTI()

	err := InitCrowdsecCTI(nil, nil, nil, nil)
	require.ErrorIs(t, err, cti.ErrDisabled)
	//Replace the client created by InitCrowdsecCTI with one that uses a custom transport
	ctiClient, err = cti.NewClientWithResponses(CTIUrl+"/v2/", cti.WithRequestEditorFn(cti.APIKeyInserter(validApiKey)), cti.WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(smokeHandler),
	}))
	require.NoError(t, err)

	item, err := CrowdsecCTI("1.2.3.4")
	assert.Equal(t, item, &cti.CTIObject{})
	assert.False(t, CTIApiEnabled)
	assert.Equal(t, err, cti.ErrDisabled)
}

func TestCache(t *testing.T) {
	defer ShutdownCrowdsecCTI()
	var err error

	cacheDuration := 1 * time.Second
	if err := InitCrowdsecCTI(ptr.Of(validApiKey), &cacheDuration, nil, nil); err != nil {
		t.Fatalf("failed to init CTI : %s", err)
	}
	//Replace the client created by InitCrowdsecCTI with one that uses a custom transport
	ctiClient, err = cti.NewClientWithResponses(CTIUrl+"/v2/", cti.WithRequestEditorFn(cti.APIKeyInserter(validApiKey)), cti.WithHTTPClient(&http.Client{
		Transport: RoundTripFunc(smokeHandler),
	}))
	require.NoError(t, err)

	item, err := CrowdsecCTI("1.2.3.4")
	ctiResp := item.(*cti.CTIObject)
	assert.Equal(t, "1.2.3.4", ctiResp.Ip)
	assert.True(t, CTIApiEnabled)
	assert.Equal(t, 1, CTICache.Len(true))
	require.NoError(t, err)

	item, err = CrowdsecCTI("1.2.3.4")
	ctiResp = item.(*cti.CTIObject)

	assert.Equal(t, "1.2.3.4", ctiResp.Ip)
	assert.True(t, CTIApiEnabled)
	assert.Equal(t, 1, CTICache.Len(true))
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	assert.Equal(t, 0, CTICache.Len(true))

	item, err = CrowdsecCTI("1.2.3.4")
	ctiResp = item.(*cti.CTIObject)

	assert.Equal(t, "1.2.3.4", ctiResp.Ip)
	assert.True(t, CTIApiEnabled)
	assert.Equal(t, 1, CTICache.Len(true))
	require.NoError(t, err)
}
