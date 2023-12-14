package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestCreateMachine(t *testing.T) {
	router, _, err := NewAPITest(t)
	if err != nil {
		log.Fatalf("unable to run local API: %s", err)
	}

	// Create machine with invalid format
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/v1/watchers", strings.NewReader("test"))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 400, w.Code)
	assert.Equal(t, "{\"message\":\"invalid character 'e' in literal true (expecting 'r')\"}", w.Body.String())

	// Create machine with invalid input
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/v1/watchers", strings.NewReader("{\"test\": \"test\"}"))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)
	assert.Equal(t, "{\"message\":\"validation failure list:\\nmachine_id in body is required\\npassword in body is required\"}", w.Body.String())

	// Create machine
	b, err := json.Marshal(MachineTest)
	if err != nil {
		log.Fatal("unable to marshal MachineTest")
	}
	body := string(b)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 201, w.Code)
	assert.Equal(t, "", w.Body.String())
}

func TestCreateMachineWithForwardedFor(t *testing.T) {
	router, config, err := NewAPITestForwardedFor(t)
	if err != nil {
		log.Fatalf("unable to run local API: %s", err)
	}
	router.TrustedPlatform = "X-Real-IP"
	// Create machine
	b, err := json.Marshal(MachineTest)
	if err != nil {
		log.Fatal("unable to marshal MachineTest")
	}
	body := string(b)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Real-Ip", "1.1.1.1")
	router.ServeHTTP(w, req)

	assert.Equal(t, 201, w.Code)
	assert.Equal(t, "", w.Body.String())

	ip, err := GetMachineIP(*MachineTest.MachineID, config.API.Server.DbConfig)
	if err != nil {
		log.Fatalf("Could not get machine IP : %s", err)
	}

	assert.Equal(t, "1.1.1.1", ip)
}

func TestCreateMachineWithForwardedForNoConfig(t *testing.T) {
	router, config, err := NewAPITest(t)
	if err != nil {
		log.Fatalf("unable to run local API: %s", err)
	}

	// Create machine
	b, err := json.Marshal(MachineTest)
	if err != nil {
		log.Fatal("unable to marshal MachineTest")
	}
	body := string(b)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Real-IP", "1.1.1.1")
	router.ServeHTTP(w, req)

	assert.Equal(t, 201, w.Code)
	assert.Equal(t, "", w.Body.String())

	ip, err := GetMachineIP(*MachineTest.MachineID, config.API.Server.DbConfig)
	if err != nil {
		log.Fatalf("Could not get machine IP : %s", err)
	}
	//For some reason, the IP is empty when running tests
	//if no forwarded-for headers are present
	assert.Equal(t, "", ip)
}

func TestCreateMachineWithoutForwardedFor(t *testing.T) {
	router, config, err := NewAPITestForwardedFor(t)
	if err != nil {
		log.Fatalf("unable to run local API: %s", err)
	}

	// Create machine
	b, err := json.Marshal(MachineTest)
	if err != nil {
		log.Fatal("unable to marshal MachineTest")
	}
	body := string(b)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 201, w.Code)
	assert.Equal(t, "", w.Body.String())

	ip, err := GetMachineIP(*MachineTest.MachineID, config.API.Server.DbConfig)
	if err != nil {
		log.Fatalf("Could not get machine IP : %s", err)
	}
	//For some reason, the IP is empty when running tests
	//if no forwarded-for headers are present
	assert.Equal(t, "", ip)
}

func TestCreateMachineAlreadyExist(t *testing.T) {
	router, _, err := NewAPITest(t)
	if err != nil {
		log.Fatalf("unable to run local API: %s", err)
	}

	body, err := CreateTestMachine(router)
	if err != nil {
		log.Fatalln(err)
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
	assert.Equal(t, "{\"message\":\"user 'test': user already exist\"}", w.Body.String())
}
