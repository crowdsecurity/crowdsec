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
	router, err := NewAPITest()
	if err != nil {
		log.Fatalf("unable to run local API: %s", err)
	}

	// Create machine with invalid format
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/watchers", strings.NewReader("test"))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 400, w.Code)
	assert.Equal(t, "{\"message\":\"invalid character 'e' in literal true (expecting 'r')\"}", w.Body.String())

	// Create machine with invalid input
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/v1/watchers", strings.NewReader("{\"test\": \"test\"}"))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)
	assert.Equal(t, "{\"message\":\"validation failure list:\\nmachine_id in body is required\\npassword in body is required\"}", w.Body.String())

	// Create machine
	b, err := json.Marshal(MachineTest)
	if err != nil {
		log.Fatalf("unable to marshal MachineTest")
	}
	body := string(b)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "", w.Body.String())

	CleanDB()
}

func TestCreateMachineAlreadyExist(t *testing.T) {
	router, err := NewAPITest()
	if err != nil {
		log.Fatalf("unable to run local API: %s", err)
	}

	body, err := CreateTestMachine(router)
	if err != nil {
		log.Fatalln(err.Error())
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
	assert.Equal(t, "{\"message\":\"user 'test': user already exist\"}", w.Body.String())

	CleanDB()
}
