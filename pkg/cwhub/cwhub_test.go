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

func TestItemStatus(t *testing.T) {
	cfg := envSetup(t)
	defer envTearDown(cfg)

	// DownloadHubIdx()
	err := UpdateHubIdx(cfg.Hub)
	require.NoError(t, err, "failed to download index")

	err = GetHubIdx(cfg.Hub)
	require.NoError(t, err, "failed to load hub index")

	// get existing map
	x := GetItemMap(COLLECTIONS)
	require.NotEmpty(t, x)

	// Get item : good and bad
	for k := range x {
		item := GetItem(COLLECTIONS, k)
		require.NotNil(t, item)

		item.Installed = true
		item.UpToDate = false
		item.Local = false
		item.Tainted = false

		txt, _ := item.status()
		require.Equal(t, "enabled,update-available", txt)

		item.Installed = false
		item.UpToDate = false
		item.Local = true
		item.Tainted = false

		txt, _ = item.status()
		require.Equal(t, "disabled,local", txt)
	}

	DisplaySummary()
}

func TestGetters(t *testing.T) {
	cfg := envSetup(t)
	defer envTearDown(cfg)

	// DownloadHubIdx()
	err := UpdateHubIdx(cfg.Hub)
	require.NoError(t, err, "failed to download index")

	err = GetHubIdx(cfg.Hub)
	require.NoError(t, err, "failed to load hub index")

	// get non existing map
	empty := GetItemMap("ratata")
	require.Nil(t, empty)

	// get existing map
	x := GetItemMap(COLLECTIONS)
	require.NotEmpty(t, x)

	// Get item : good and bad
	for k := range x {
		empty := GetItem(COLLECTIONS, k+"nope")
		require.Nil(t, empty)

		item := GetItem(COLLECTIONS, k)
		require.NotNil(t, item)

		// Add item and get it
		item.Name += "nope"
		err := AddItem(COLLECTIONS, *item)
		require.NoError(t, err)

		newitem := GetItem(COLLECTIONS, item.Name)
		require.NotNil(t, newitem)

		err = AddItem("ratata", *item)
		cstest.RequireErrorContains(t, err, "ItemType ratata is unknown")
	}
}

func TestIndexDownload(t *testing.T) {
	cfg := envSetup(t)
	defer envTearDown(cfg)

	// DownloadHubIdx()
	err := UpdateHubIdx(cfg.Hub)
	require.NoError(t, err, "failed to download index")

	err = GetHubIdx(cfg.Hub)
	require.NoError(t, err, "failed to load hub index")
}

func getTestCfg() *csconfig.Config {
	cfg := &csconfig.Config{Hub: &csconfig.Hub{}}
	cfg.Hub.InstallDir, _ = filepath.Abs("./install")
	cfg.Hub.HubDir, _ = filepath.Abs("./hubdir")
	cfg.Hub.HubIndexFile = filepath.Clean("./hubdir/.index.json")

	return cfg
}

func envSetup(t *testing.T) *csconfig.Config {
	resetResponseByPath()
	log.SetLevel(log.DebugLevel)

	cfg := getTestCfg()

	defaultTransport := http.DefaultClient.Transport

	t.Cleanup(func() {
		http.DefaultClient.Transport = defaultTransport
	})

	// Mock the http client
	http.DefaultClient.Transport = newMockTransport()

	err := os.MkdirAll(cfg.Hub.InstallDir, 0700)
	require.NoError(t, err)

	err = os.MkdirAll(cfg.Hub.HubDir, 0700)
	require.NoError(t, err)

	err = UpdateHubIdx(cfg.Hub)
	require.NoError(t, err)

	// if err := os.RemoveAll(cfg.Hub.InstallDir); err != nil {
	// 	log.Fatalf("failed to remove %s : %s", cfg.Hub.InstallDir, err)
	// }
	// if err := os.MkdirAll(cfg.Hub.InstallDir, 0700); err != nil {
	// 	log.Fatalf("failed to mkdir %s : %s", cfg.Hub.InstallDir, err)
	// }
	return cfg
}

func envTearDown(cfg *csconfig.Config) {
	if err := os.RemoveAll(cfg.Hub.InstallDir); err != nil {
		log.Fatalf("failed to remove %s : %s", cfg.Hub.InstallDir, err)
	}

	if err := os.RemoveAll(cfg.Hub.HubDir); err != nil {
		log.Fatalf("failed to remove %s : %s", cfg.Hub.HubDir, err)
	}
}

func testInstallItem(cfg *csconfig.Hub, t *testing.T, item Item) {
	// Install the parser
	err := DownloadLatest(cfg, &item, false, false)
	require.NoError(t, err, "failed to download %s", item.Name)

	err, _ = LocalSync(cfg)
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, hubIdx[item.Type][item.Name].UpToDate, "%s should be up-to-date", item.Name)
	assert.False(t, hubIdx[item.Type][item.Name].Installed, "%s should not be installed", item.Name)
	assert.False(t, hubIdx[item.Type][item.Name].Tainted, "%s should not be tainted", item.Name)

	err = EnableItem(cfg, &item)
	require.NoError(t, err, "failed to enable %s", item.Name)

	err, _ = LocalSync(cfg)
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, hubIdx[item.Type][item.Name].Installed, "%s should be installed", item.Name)
}

func testTaintItem(cfg *csconfig.Hub, t *testing.T, item Item) {
	assert.False(t, hubIdx[item.Type][item.Name].Tainted, "%s should not be tainted", item.Name)

	f, err := os.OpenFile(item.LocalPath, os.O_APPEND|os.O_WRONLY, 0600)
	require.NoError(t, err, "failed to open %s (%s)", item.LocalPath, item.Name)

	defer f.Close()

	_, err = f.WriteString("tainted")
	require.NoError(t, err, "failed to write to %s (%s)", item.LocalPath, item.Name)

	// Local sync and check status
	err, _ = LocalSync(cfg)
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, hubIdx[item.Type][item.Name].Tainted, "%s should be tainted", item.Name)
}

func testUpdateItem(cfg *csconfig.Hub, t *testing.T, item Item) {
	assert.False(t, hubIdx[item.Type][item.Name].UpToDate, "%s should not be up-to-date", item.Name)

	// Update it + check status
	err := DownloadLatest(cfg, &item, true, true)
	require.NoError(t, err, "failed to update %s", item.Name)

	// Local sync and check status
	err, _ = LocalSync(cfg)
	require.NoError(t, err, "failed to run localSync")

	assert.True(t, hubIdx[item.Type][item.Name].UpToDate, "%s should be up-to-date", item.Name)
	assert.False(t, hubIdx[item.Type][item.Name].Tainted, "%s should not be tainted anymore", item.Name)
}

func testDisableItem(cfg *csconfig.Hub, t *testing.T, item Item) {
	assert.True(t, hubIdx[item.Type][item.Name].Installed, "%s should be installed", item.Name)

	// Remove
	err := DisableItem(cfg, &item, false, false)
	require.NoError(t, err, "failed to disable %s", item.Name)

	// Local sync and check status
	err, warns := LocalSync(cfg)
	require.NoError(t, err, "failed to run localSync")
	require.Empty(t, warns, "unexpected warnings : %+v", warns)

	assert.False(t, hubIdx[item.Type][item.Name].Tainted, "%s should not be tainted anymore", item.Name)
	assert.False(t, hubIdx[item.Type][item.Name].Installed, "%s should not be installed anymore", item.Name)
	assert.True(t, hubIdx[item.Type][item.Name].Downloaded, "%s should still be downloaded", item.Name)

	// Purge
	err = DisableItem(cfg, &item, true, false)
	require.NoError(t, err, "failed to purge %s", item.Name)

	// Local sync and check status
	err, warns = LocalSync(cfg)
	require.NoError(t, err, "failed to run localSync")
	require.Empty(t, warns, "unexpected warnings : %+v", warns)

	assert.False(t, hubIdx[item.Type][item.Name].Installed, "%s should not be installed anymore", item.Name)
	assert.False(t, hubIdx[item.Type][item.Name].Downloaded, "%s should not be downloaded", item.Name)
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
	cfg := envSetup(t)
	defer envTearDown(cfg)

	getHubIdxOrFail(t)
	// map iteration is random by itself
	for _, it := range hubIdx[PARSERS] {
		testInstallItem(cfg.Hub, t, it)
		it = hubIdx[PARSERS][it.Name]
		_ = GetHubStatusForItemType(PARSERS, it.Name, false)
		testTaintItem(cfg.Hub, t, it)
		it = hubIdx[PARSERS][it.Name]
		_ = GetHubStatusForItemType(PARSERS, it.Name, false)
		testUpdateItem(cfg.Hub, t, it)
		it = hubIdx[PARSERS][it.Name]
		testDisableItem(cfg.Hub, t, it)
		it = hubIdx[PARSERS][it.Name]

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
	cfg := envSetup(t)
	defer envTearDown(cfg)

	getHubIdxOrFail(t)
	// map iteration is random by itself
	for _, it := range hubIdx[COLLECTIONS] {
		testInstallItem(cfg.Hub, t, it)
		it = hubIdx[COLLECTIONS][it.Name]
		testTaintItem(cfg.Hub, t, it)
		it = hubIdx[COLLECTIONS][it.Name]
		testUpdateItem(cfg.Hub, t, it)
		it = hubIdx[COLLECTIONS][it.Name]
		testDisableItem(cfg.Hub, t, it)

		it = hubIdx[COLLECTIONS][it.Name]
		x := GetHubStatusForItemType(COLLECTIONS, it.Name, false)
		log.Infof("%+v", x)

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
