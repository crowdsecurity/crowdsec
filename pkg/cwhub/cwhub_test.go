package cwhub

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

const mockURLTemplate = "https://hub-cdn.crowdsec.net/%s/%s"

/*
 To test :
  - Download 'first' hub index
  - Update hub index
  - Install collection + list content
  - Taint existing parser + list
  - Upgrade collection
*/

var responseByPath map[string]string

// testHub initializes a temporary hub with an empty json file, optionally updating it.
func testHub(t *testing.T, update bool) *Hub {
	tmpDir, err := os.MkdirTemp("", "testhub")
	require.NoError(t, err)

	local := &csconfig.LocalHubCfg{
		HubDir:         filepath.Join(tmpDir, "crowdsec", "hub"),
		HubIndexFile:   filepath.Join(tmpDir, "crowdsec", "hub", ".index.json"),
		InstallDir:     filepath.Join(tmpDir, "crowdsec"),
		InstallDataDir: filepath.Join(tmpDir, "installed-data"),
	}

	err = os.MkdirAll(local.HubDir, 0o700)
	require.NoError(t, err)

	err = os.MkdirAll(local.InstallDir, 0o700)
	require.NoError(t, err)

	err = os.MkdirAll(local.InstallDataDir, 0o700)
	require.NoError(t, err)

	err = os.WriteFile(local.HubIndexFile, []byte("{}"), 0o644)
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	remote := &RemoteHubCfg{
		Branch:      "master",
		URLTemplate: mockURLTemplate,
		IndexPath:   ".index.json",
	}

	hub, err := NewHub(local, remote, update, log.StandardLogger())
	require.NoError(t, err)

	return hub
}

// envSetup initializes the temporary hub and mocks the http client.
func envSetup(t *testing.T) *Hub {
	setResponseByPath()
	log.SetLevel(log.DebugLevel)

	defaultTransport := hubClient.Transport

	t.Cleanup(func() {
		hubClient.Transport = defaultTransport
	})

	// Mock the http client
	hubClient.Transport = newMockTransport()

	hub := testHub(t, true)

	return hub
}

type mockTransport struct{}

func newMockTransport() http.RoundTripper {
	return &mockTransport{}
}

// Implement http.RoundTripper.
func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Create mocked http.Response
	response := &http.Response{
		Header:     make(http.Header),
		Request:    req,
		StatusCode: http.StatusOK,
	}
	response.Header.Set("Content-Type", "application/json")

	log.Infof("---> %s", req.URL.Path)

	// FAKE PARSER
	resp, ok := responseByPath[req.URL.Path]
	if !ok {
		log.Fatalf("unexpected url :/ %s", req.URL.Path)
	}

	response.Body = io.NopCloser(strings.NewReader(resp))

	return response, nil
}

func fileToStringX(path string) string {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}

	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

func setResponseByPath() {
	responseByPath = map[string]string{
		"/master/parsers/s01-parse/crowdsecurity/foobar_parser.yaml":    fileToStringX("./testdata/foobar_parser.yaml"),
		"/master/parsers/s01-parse/crowdsecurity/foobar_subparser.yaml": fileToStringX("./testdata/foobar_parser.yaml"),
		"/master/collections/crowdsecurity/test_collection.yaml":        fileToStringX("./testdata/collection_v1.yaml"),
		"/master/.index.json": fileToStringX("./testdata/index1.json"),
		"/master/scenarios/crowdsecurity/foobar_scenario.yaml": `filter: true
name: crowdsecurity/foobar_scenario`,
		"/master/scenarios/crowdsecurity/barfoo_scenario.yaml": `filter: true
name: crowdsecurity/foobar_scenario`,
		"/master/collections/crowdsecurity/foobar_subcollection.yaml": `
blah: blalala
qwe: jejwejejw`,
		"/master/collections/crowdsecurity/foobar.yaml": `
blah: blalala
qwe: jejwejejw`,
	}
}
