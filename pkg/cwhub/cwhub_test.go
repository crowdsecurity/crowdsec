package cwhub

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	log "github.com/sirupsen/logrus"
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

	err := UpdateHubIdx(cfg.Hub)
	//DownloadHubIdx()
	if err != nil {
		t.Fatalf("failed to download index : %s", err)
	}
	if err := GetHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to load hub index : %s", err)
	}

	//get existing map
	x := GetItemMap(COLLECTIONS)
	if len(x) == 0 {
		t.Fatalf("expected non empty result")
	}

	//Get item : good and bad
	for k := range x {
		item := GetItem(COLLECTIONS, k)
		if item == nil {
			t.Fatalf("expected item")
		}
		item.Installed = true
		item.UpToDate = false
		item.Local = false
		item.Tainted = false
		txt, _, _, _ := ItemStatus(*item)
		if txt != "enabled,update-available" {
			t.Fatalf("got '%s'", txt)
		}

		item.Installed = false
		item.UpToDate = false
		item.Local = true
		item.Tainted = false
		txt, _, _, _ = ItemStatus(*item)
		if txt != "disabled,local" {
			t.Fatalf("got '%s'", txt)
		}

		break
	}
	DisplaySummary()
}

func TestGetters(t *testing.T) {
	cfg := envSetup(t)
	defer envTearDown(cfg)

	err := UpdateHubIdx(cfg.Hub)
	//DownloadHubIdx()
	if err != nil {
		t.Fatalf("failed to download index : %s", err)
	}
	if err := GetHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to load hub index : %s", err)
	}

	//get non existing map
	empty := GetItemMap("ratata")
	if empty != nil {
		t.Fatalf("expected nil result")
	}
	//get existing map
	x := GetItemMap(COLLECTIONS)
	if len(x) == 0 {
		t.Fatalf("expected non empty result")
	}

	//Get item : good and bad
	for k := range x {
		empty := GetItem(COLLECTIONS, k+"nope")
		if empty != nil {
			t.Fatalf("expected empty item")
		}

		item := GetItem(COLLECTIONS, k)
		if item == nil {
			t.Fatalf("expected non empty item")
		}

		//Add item and get it
		item.Name += "nope"
		if err := AddItem(COLLECTIONS, *item); err != nil {
			t.Fatalf("didn't expect error : %s", err)
		}

		newitem := GetItem(COLLECTIONS, item.Name)
		if newitem == nil {
			t.Fatalf("expected non empty item")
		}

		//Add bad item
		if err := AddItem("ratata", *item); err != nil {
			if fmt.Sprintf("%s", err) != "ItemType ratata is unknown" {
				t.Fatalf("unexpected error")
			}
		} else {
			t.Fatalf("Expected error")
		}

		break
	}

}

func TestIndexDownload(t *testing.T) {
	cfg := envSetup(t)
	defer envTearDown(cfg)

	err := UpdateHubIdx(cfg.Hub)
	//DownloadHubIdx()
	if err != nil {
		t.Fatalf("failed to download index : %s", err)
	}
	if err := GetHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to load hub index : %s", err)
	}
}

func getTestCfg() (cfg *csconfig.Config) {
	cfg = &csconfig.Config{Hub: &csconfig.Hub{}}
	cfg.Hub.ConfigDir, _ = filepath.Abs("./install")
	cfg.Hub.HubDir, _ = filepath.Abs("./hubdir")
	cfg.Hub.HubIndexFile = filepath.Clean("./hubdir/.index.json")
	return
}

func envSetup(t *testing.T) *csconfig.Config {
	resetResponseByPath()
	log.SetLevel(log.DebugLevel)
	cfg := getTestCfg()

	defaultTransport := http.DefaultClient.Transport
	t.Cleanup(func() {
		http.DefaultClient.Transport = defaultTransport
	})

	//Mock the http client
	http.DefaultClient.Transport = newMockTransport()

	if err := os.MkdirAll(cfg.Hub.ConfigDir, 0700); err != nil {
		log.Fatalf("mkdir : %s", err)
	}

	if err := os.MkdirAll(cfg.Hub.HubDir, 0700); err != nil {
		log.Fatalf("failed to mkdir %s : %s", cfg.Hub.HubDir, err)
	}

	if err := UpdateHubIdx(cfg.Hub); err != nil {
		log.Fatalf("failed to download index : %s", err)
	}

	// if err := os.RemoveAll(cfg.Hub.InstallDir); err != nil {
	// 	log.Fatalf("failed to remove %s : %s", cfg.Hub.InstallDir, err)
	// }
	// if err := os.MkdirAll(cfg.Hub.InstallDir, 0700); err != nil {
	// 	log.Fatalf("failed to mkdir %s : %s", cfg.Hub.InstallDir, err)
	// }
	return cfg
}


func envTearDown(cfg *csconfig.Config) {
	if err := os.RemoveAll(cfg.Hub.ConfigDir); err != nil {
		log.Fatalf("failed to remove %s : %s", cfg.Hub.ConfigDir, err)
	}

	if err := os.RemoveAll(cfg.Hub.HubDir); err != nil {
		log.Fatalf("failed to remove %s : %s", cfg.Hub.HubDir, err)
	}
}


func testInstallItem(cfg *csconfig.Hub, t *testing.T, item Item) {

	//Install the parser
	item, err := DownloadLatest(cfg, item, false, false)
	if err != nil {
		t.Fatalf("error while downloading %s : %v", item.Name, err)
	}
	if err, _ := LocalSync(cfg); err != nil {
		t.Fatalf("taint: failed to run localSync : %s", err)
	}
	if !hubIdx[item.Type][item.Name].UpToDate {
		t.Fatalf("download: %s should be up-to-date", item.Name)
	}
	if hubIdx[item.Type][item.Name].Installed {
		t.Fatalf("download: %s should not be installed", item.Name)
	}
	if hubIdx[item.Type][item.Name].Tainted {
		t.Fatalf("download: %s should not be tainted", item.Name)
	}

	item, err = EnableItem(cfg, item)
	if err != nil {
		t.Fatalf("error while enabling %s : %v.", item.Name, err)
	}
	if err, _ := LocalSync(cfg); err != nil {
		t.Fatalf("taint: failed to run localSync : %s", err)
	}
	if !hubIdx[item.Type][item.Name].Installed {
		t.Fatalf("install: %s should be installed", item.Name)
	}
}

func testTaintItem(cfg *csconfig.Hub, t *testing.T, item Item) {
	if hubIdx[item.Type][item.Name].Tainted {
		t.Fatalf("pre-taint: %s should not be tainted", item.Name)
	}
	f, err := os.OpenFile(item.LocalPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("(taint) opening %s (%s) : %s", item.LocalPath, item.Name, err)
	}
	defer f.Close()

	if _, err = f.WriteString("tainted"); err != nil {
		t.Fatalf("tainting %s : %s", item.Name, err)
	}
	//Local sync and check status
	if err, _ := LocalSync(cfg); err != nil {
		t.Fatalf("taint: failed to run localSync : %s", err)
	}
	if !hubIdx[item.Type][item.Name].Tainted {
		t.Fatalf("taint: %s should be tainted", item.Name)
	}
}

func testUpdateItem(cfg *csconfig.Hub, t *testing.T, item Item) {

	if hubIdx[item.Type][item.Name].UpToDate {
		t.Fatalf("update: %s should NOT be up-to-date", item.Name)
	}
	//Update it + check status
	item, err := DownloadLatest(cfg, item, true, true)
	if err != nil {
		t.Fatalf("failed to update %s : %s", item.Name, err)
	}
	//Local sync and check status
	if err, _ := LocalSync(cfg); err != nil {
		t.Fatalf("failed to run localSync : %s", err)
	}
	if !hubIdx[item.Type][item.Name].UpToDate {
		t.Fatalf("update: %s should be up-to-date", item.Name)
	}
	if hubIdx[item.Type][item.Name].Tainted {
		t.Fatalf("update: %s should not be tainted anymore", item.Name)
	}
}

func testDisableItem(cfg *csconfig.Hub, t *testing.T, item Item) {
	if !item.Installed {
		t.Fatalf("disable: %s should be installed", item.Name)
	}
	//Remove
	item, err := DisableItem(cfg, item, false, false)
	if err != nil {
		t.Fatalf("failed to disable item : %v", err)
	}
	//Local sync and check status
	if err, warns := LocalSync(cfg); err != nil || len(warns) > 0 {
		t.Fatalf("failed to run localSync : %s (%+v)", err, warns)
	}
	if hubIdx[item.Type][item.Name].Tainted {
		t.Fatalf("disable: %s should not be tainted anymore", item.Name)
	}
	if hubIdx[item.Type][item.Name].Installed {
		t.Fatalf("disable: %s should not be installed anymore", item.Name)
	}
	if !hubIdx[item.Type][item.Name].Downloaded {
		t.Fatalf("disable: %s should still be downloaded", item.Name)
	}
	//Purge
	item, err = DisableItem(cfg, item, true, false)
	if err != nil {
		t.Fatalf("failed to purge item : %v", err)
	}
	//Local sync and check status
	if err, warns := LocalSync(cfg); err != nil || len(warns) > 0 {
		t.Fatalf("failed to run localSync : %s (%+v)", err, warns)
	}
	if hubIdx[item.Type][item.Name].Installed {
		t.Fatalf("disable: %s should not be installed anymore", item.Name)
	}
	if hubIdx[item.Type][item.Name].Downloaded {
		t.Fatalf("disable: %s should not be downloaded", item.Name)
	}
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
	//map iteration is random by itself
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
	//map iteration is random by itself
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
		log.Printf("%+v", x)
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
	responseBody := ""
	log.Printf("---> %s", req.URL.Path)

	/*FAKE PARSER*/
	if resp, ok := responseByPath[req.URL.Path]; ok {
		responseBody = resp
	} else {
		log.Fatalf("unexpected url :/ %s", req.URL.Path)
	}

	response.Body = io.NopCloser(strings.NewReader(responseBody))
	return response, nil
}

func fileToStringX(path string) string {
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		if data, err := io.ReadAll(f); err == nil {
			return strings.ReplaceAll(string(data), "\r\n", "\n")
		} else {
			panic(err)
		}
	} else {
		panic(err)
	}
}

func resetResponseByPath() {
	responseByPath = map[string]string{
		"/master/parsers/s01-parse/crowdsecurity/foobar_parser.yaml":    fileToStringX("./tests/foobar_parser.yaml"),
		"/master/parsers/s01-parse/crowdsecurity/foobar_subparser.yaml": fileToStringX("./tests/foobar_parser.yaml"),
		"/master/collections/crowdsecurity/test_collection.yaml":        fileToStringX("./tests/collection_v1.yaml"),
		"/master/.index.json": fileToStringX("./tests/index1.json"),
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
