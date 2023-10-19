package cwhub

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

/*
 To test :
  - Download 'first' hub index
  - Update hub index
  - Install collection + list content
  - Taint existing parser + list
  - Upgrade collection
*/

var responseByPath map[string]string

// testHub initializes a temporary hub with an empty json file, optionally updating it
func testHub(t *testing.T, update bool) *Hub {
	tmpDir, err := os.MkdirTemp("", "testhub")
	require.NoError(t, err)

	hubCfg := &csconfig.HubCfg{
		HubDir:         filepath.Join(tmpDir, "crowdsec", "hub"),
		HubIndexFile:   filepath.Join(tmpDir, "crowdsec", "hub", ".index.json"),
		InstallDir:     filepath.Join(tmpDir, "crowdsec"),
		InstallDataDir: filepath.Join(tmpDir, "installed-data"),
	}

	err = os.MkdirAll(hubCfg.HubDir, 0o700)
	require.NoError(t, err)

	err = os.MkdirAll(hubCfg.InstallDir, 0o700)
	require.NoError(t, err)

	err = os.MkdirAll(hubCfg.InstallDataDir, 0o700)
	require.NoError(t, err)

	index, err := os.Create(hubCfg.HubIndexFile)
	require.NoError(t, err)

	_, err = index.WriteString(`{}`)
	require.NoError(t, err)

	index.Close()

	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	constructor := InitHub

	if update {
		constructor = InitHubUpdate
	}

	hub, err := constructor(hubCfg)
	require.NoError(t, err)

	return hub
}

func envSetup(t *testing.T) *Hub {
	resetResponseByPath()
	log.SetLevel(log.DebugLevel)

	defaultTransport := http.DefaultClient.Transport

	t.Cleanup(func() {
		http.DefaultClient.Transport = defaultTransport
	})

	// Mock the http client
	http.DefaultClient.Transport = newMockTransport()

	hub := testHub(t, true)

	return hub
}

func TestItemStatus(t *testing.T) {
	hub := envSetup(t)

	// get existing map
	x := hub.GetItemMap(COLLECTIONS)
	require.NotEmpty(t, x)

	// Get item : good and bad
	for k := range x {
		item := hub.GetItem(COLLECTIONS, k)
		require.NotNil(t, item)

		item.Installed = true
		item.UpToDate = false
		item.Local = false
		item.Tainted = false

		txt, _ := item.Status()
		require.Equal(t, "enabled,update-available", txt)

		item.Installed = false
		item.UpToDate = false
		item.Local = true
		item.Tainted = false

		txt, _ = item.Status()
		require.Equal(t, "disabled,local", txt)
	}

	err := DisplaySummary()
	require.NoError(t, err)
}

func TestGetters(t *testing.T) {
	hub := envSetup(t)

	// get non existing map
	empty := hub.GetItemMap("ratata")
	require.Nil(t, empty)

	// get existing map
	x := hub.GetItemMap(COLLECTIONS)
	require.NotEmpty(t, x)

	// Get item : good and bad
	for k := range x {
		empty := hub.GetItem(COLLECTIONS, k+"nope")
		require.Nil(t, empty)

		item := hub.GetItem(COLLECTIONS, k)
		require.NotNil(t, item)

		// Add item and get it
		item.Name += "nope"
		err := hub.AddItem(COLLECTIONS, *item)
		require.NoError(t, err)

		newitem := hub.GetItem(COLLECTIONS, item.Name)
		require.NotNil(t, newitem)

		err = hub.AddItem("ratata", *item)
		cstest.RequireErrorContains(t, err, "ItemType ratata is unknown")
	}
}

func TestIndexDownload(t *testing.T) {
	hub := envSetup(t)

	_, err := InitHubUpdate(hub.cfg)
	require.NoError(t, err, "failed to download index")

	_, err = GetHub()
	require.NoError(t, err, "failed to load hub index")
}

func testInstallItem(hub *Hub, t *testing.T, item Item) {
	// Install the parser
	err := hub.DownloadLatest(&item, false, false)
	require.NoError(t, err, "failed to download %s", item.Name)

	_, err = hub.LocalSync()
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, hub.Items[item.Type][item.Name].UpToDate, "%s should be up-to-date", item.Name)
	assert.False(t, hub.Items[item.Type][item.Name].Installed, "%s should not be installed", item.Name)
	assert.False(t, hub.Items[item.Type][item.Name].Tainted, "%s should not be tainted", item.Name)

	err = hub.EnableItem(&item)
	require.NoError(t, err, "failed to enable %s", item.Name)

	_, err = hub.LocalSync()
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, hub.Items[item.Type][item.Name].Installed, "%s should be installed", item.Name)
}

func testTaintItem(hub *Hub, t *testing.T, item Item) {
	assert.False(t, hub.Items[item.Type][item.Name].Tainted, "%s should not be tainted", item.Name)

	f, err := os.OpenFile(item.LocalPath, os.O_APPEND|os.O_WRONLY, 0600)
	require.NoError(t, err, "failed to open %s (%s)", item.LocalPath, item.Name)

	defer f.Close()

	_, err = f.WriteString("tainted")
	require.NoError(t, err, "failed to write to %s (%s)", item.LocalPath, item.Name)

	// Local sync and check status
	_, err = hub.LocalSync()
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, hub.Items[item.Type][item.Name].Tainted, "%s should be tainted", item.Name)
}

func testUpdateItem(hub *Hub, t *testing.T, item Item) {
	assert.False(t, hub.Items[item.Type][item.Name].UpToDate, "%s should not be up-to-date", item.Name)

	// Update it + check status
	err := hub.DownloadLatest(&item, true, true)
	require.NoError(t, err, "failed to update %s", item.Name)

	// Local sync and check status
	_, err = hub.LocalSync()
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, hub.Items[item.Type][item.Name].UpToDate, "%s should be up-to-date", item.Name)
	assert.False(t, hub.Items[item.Type][item.Name].Tainted, "%s should not be tainted anymore", item.Name)
}

func testDisableItem(hub *Hub, t *testing.T, item Item) {
	assert.True(t, hub.Items[item.Type][item.Name].Installed, "%s should be installed", item.Name)

	// Remove
	err := hub.DisableItem(&item, false, false)
	require.NoError(t, err, "failed to disable %s", item.Name)

	// Local sync and check status
	warns, err := hub.LocalSync()
	require.NoError(t, err, "failed to run localSync")
	require.Empty(t, warns, "unexpected warnings : %+v", warns)

	assert.False(t, hub.Items[item.Type][item.Name].Tainted, "%s should not be tainted anymore", item.Name)
	assert.False(t, hub.Items[item.Type][item.Name].Installed, "%s should not be installed anymore", item.Name)
	assert.True(t, hub.Items[item.Type][item.Name].Downloaded, "%s should still be downloaded", item.Name)

	// Purge
	err = hub.DisableItem(&item, true, false)
	require.NoError(t, err, "failed to purge %s", item.Name)

	// Local sync and check status
	warns, err = hub.LocalSync()
	require.NoError(t, err, "failed to run localSync")
	require.Empty(t, warns, "unexpected warnings : %+v", warns)

	assert.False(t, hub.Items[item.Type][item.Name].Installed, "%s should not be installed anymore", item.Name)
	assert.False(t, hub.Items[item.Type][item.Name].Downloaded, "%s should not be downloaded", item.Name)
}

func TestInstallParser(t *testing.T) {
	/*
	 - install a random parser
	 - check its status
	 - taint it
	 - check its status
	 - force update it
	 - check its status
	 - remove it
	*/
	hub := envSetup(t)

	// map iteration is random by itself
	for _, it := range hub.Items[PARSERS] {
		testInstallItem(hub, t, it)
		it = hub.Items[PARSERS][it.Name]
		testTaintItem(hub, t, it)
		it = hub.Items[PARSERS][it.Name]
		testUpdateItem(hub, t, it)
		it = hub.Items[PARSERS][it.Name]
		testDisableItem(hub, t, it)
		it = hub.Items[PARSERS][it.Name]

		break
	}
}

func TestInstallCollection(t *testing.T) {
	/*
	 - install a random parser
	 - check its status
	 - taint it
	 - check its status
	 - force update it
	 - check its status
	 - remove it
	*/
	hub := envSetup(t)

	// map iteration is random by itself
	for _, it := range hub.Items[COLLECTIONS] {
		testInstallItem(hub, t, it)
		it = hub.Items[COLLECTIONS][it.Name]
		testTaintItem(hub, t, it)
		it = hub.Items[COLLECTIONS][it.Name]
		testUpdateItem(hub, t, it)
		it = hub.Items[COLLECTIONS][it.Name]
		testDisableItem(hub, t, it)

		break
	}
}

type mockTransport struct{}

func newMockTransport() http.RoundTripper {
	return &mockTransport{}
}

// Implement http.RoundTripper
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

func resetResponseByPath() {
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
