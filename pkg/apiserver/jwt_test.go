package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLogin(t *testing.T) {
	router, err := NewAPITest()
	if err != nil {
		log.Fatalf("unable to run local API: %s", err)
	}

	body, err := CreateTestMachine(router)
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Login with machine not validated yet
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/watchers/login", strings.NewReader(body))
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.Equal(t, "{\"code\":401,\"message\":\"not valid user\"}", w.Body.String())

	// Login with machine not exist
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/watchers/login", strings.NewReader("{\"machine_id\": \"test1\", \"password\": \"test1\"}"))
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.Equal(t, "{\"code\":401,\"message\":\"incorrect Username or Password\"}", w.Body.String())

	// Login with invalid body
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/watchers/login", strings.NewReader("test"))
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.Equal(t, "{\"code\":401,\"message\":\"missing : invalid character 'e' in literal true (expecting 'r')\"}", w.Body.String())

	// Login with invalid format
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/watchers/login", strings.NewReader("{\"machine_id\": \"test1\"}"))
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.Equal(t, "{\"code\":401,\"message\":\"input format error\"}", w.Body.String())

	//Validate machine
	err = ValidateMachine("test")
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Login with invalid password
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/watchers/login", strings.NewReader("{\"machine_id\": \"test\", \"password\": \"test1\"}"))
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.Equal(t, "{\"code\":401,\"message\":\"incorrect Username or Password\"}", w.Body.String())

	// Login with valid machine
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/watchers/login", strings.NewReader(body))
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "\"token\"")
	assert.Contains(t, w.Body.String(), "\"expire\"")

	// Login with valid machine + scenarios
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/watchers/login", strings.NewReader("{\"machine_id\": \"test\", \"password\": \"test\", \"scenarios\": [\"crowdsecurity/test\", \"crowdsecurity/test2\"]}"))
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "\"token\"")
	assert.Contains(t, w.Body.String(), "\"expire\"")

	CleanDB()
}
