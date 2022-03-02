package cwhub

import (
	"fmt"
	"io/ioutil"
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

func TestItemStatus(t *testing.T) {
	cfg := test_prepenv()

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
			log.Fatalf("got '%s'", txt)
		}

		item.Installed = false
		item.UpToDate = false
		item.Local = true
		item.Tainted = false
		txt, _, _, _ = ItemStatus(*item)
		if txt != "disabled,local" {
			log.Fatalf("got '%s'", txt)
		}

		break
	}
	DisplaySummary()
}

func TestGetters(t *testing.T) {
	cfg := test_prepenv()

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
	for k, _ := range x {
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

	cfg := test_prepenv()

	err := UpdateHubIdx(cfg.Hub)
	//DownloadHubIdx()
	if err != nil {
		t.Fatalf("failed to download index : %s", err)
	}
	if err := GetHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to load hub index : %s", err)
	}
}

func test_prepenv() *csconfig.Config {
	log.SetLevel(log.DebugLevel)

	var cfg = &csconfig.Config{}
	cfg.Hub = &csconfig.Hub{}
	cfg.Hub.ConfigDir, _ = filepath.Abs("./install")
	cfg.Hub.HubDir, _ = filepath.Abs("./hubdir")
	cfg.Hub.HubIndexFile = filepath.Clean("./hubdir/.index.json")

	//Mock the http client
	http.DefaultClient.Transport = newMockTransport()

	if err := os.RemoveAll(cfg.Hub.ConfigDir); err != nil {
		log.Fatalf("failed to remove %s : %s", cfg.Hub.ConfigDir, err)
	}

	if err := os.MkdirAll(cfg.Hub.ConfigDir, 0700); err != nil {
		log.Fatalf("mkdir : %s", err)
	}

	if err := os.RemoveAll(cfg.Hub.HubDir); err != nil {
		log.Fatalf("failed to remove %s : %s", cfg.Hub.HubDir, err)
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

	if _, err = f.WriteString("tainted"); err != nil {
		t.Fatalf("tainting %s : %s", item.Name, err)
	}
	f.Close()
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
	cfg := test_prepenv()

	if err := GetHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to load hub index")
	}
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
	cfg := test_prepenv()

	if err := GetHubIdx(cfg.Hub); err != nil {
		t.Fatalf("failed to load hub index")
	}
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
	if req.URL.Path == "/master/parsers/s01-parse/crowdsecurity/foobar_parser.yaml" {
		responseBody = `onsuccess: next_stage
filter: evt.Parsed.program == 'foobar_parser'
name: crowdsecurity/foobar_parser
#debug: true
description: A parser for foobar_parser WAF
grok:
  name: foobar_parser
  apply_on: message
`

	} else if req.URL.Path == "/master/parsers/s01-parse/crowdsecurity/foobar_subparser.yaml" {
		responseBody = `onsuccess: next_stage
filter: evt.Parsed.program == 'foobar_parser'
name: crowdsecurity/foobar_parser
#debug: true
description: A parser for foobar_parser WAF
grok:
  name: foobar_parser
  apply_on: message
`
		/*FAKE SCENARIO*/

	} else if req.URL.Path == "/master/scenarios/crowdsecurity/foobar_scenario.yaml" {
		responseBody = `filter: true
name: crowdsecurity/foobar_scenario`
		/*FAKE COLLECTIONS*/
	} else if req.URL.Path == "/master/collections/crowdsecurity/foobar.yaml" {
		responseBody = `
blah: blalala
qwe: jejwejejw`
	} else if req.URL.Path == "/master/collections/crowdsecurity/foobar_subcollection.yaml" {
		responseBody = `
blah: blalala
qwe: jejwejejw`
	} else if req.URL.Path == "/master/.index.json" {
		responseBody =
			`{
				"collections": {
				 "crowdsecurity/foobar": {
				  "path": "collections/crowdsecurity/foobar.yaml",
				  "version": "0.1",
				  "versions": {
				   "0.1": {
					"digest": "786c9490e4dd234453e53aa9bb7d28c60668e31c3c0c71a7dd6d0abbfa60261a",
					"deprecated": false
				   }
				  },
				  "long_description": "bG9uZyBkZXNjcmlwdGlvbgo=",
				  "content": "bG9uZyBkZXNjcmlwdGlvbgo=",
				  "description": "foobar collection : foobar",
				  "author": "crowdsecurity",
				  "labels": null,
				  "collections" : ["crowdsecurity/foobar_subcollection"],
				  "parsers": [
				   "crowdsecurity/foobar_parser"
				  ],
				  "scenarios": [
				   "crowdsecurity/foobar_scenario"
				  ]
				 },
				 "crowdsecurity/foobar_subcollection": {
					"path": "collections/crowdsecurity/foobar_subcollection.yaml",
					"version": "0.1",
					"versions": {
					 "0.1": {
					  "digest": "786c9490e4dd234453e53aa9bb7d28c60668e31c3c0c71a7dd6d0abbfa60261a",
					  "deprecated": false
					 }
					},
					"long_description": "bG9uZyBkZXNjcmlwdGlvbgo=",
					"content": "bG9uZyBkZXNjcmlwdGlvbgo=",
					"description": "foobar collection : foobar",
					"author": "crowdsecurity",
					"labels": null,
					"parsers": [
					 "crowdsecurity/foobar_subparser"
					]
				   }
				},
				"parsers": {
				 "crowdsecurity/foobar_parser": {
				  "path": "parsers/s01-parse/crowdsecurity/foobar_parser.yaml",
				  "stage": "s01-parse",
				  "version": "0.1",
				  "versions": {
				   "0.1": {
					"digest": "7d72765baa7227095d8e83803d81f2a8f383e5808f1a4d72deb425352afd59ae",
					"deprecated": false
				   }
				  },
				  "long_description": "bG9uZyBkZXNjcmlwdGlvbgo=",
				  "content": "bG9uZyBkZXNjcmlwdGlvbgo=",
				  "description": "A foobar parser",
				  "author": "crowdsecurity",
				  "labels": null
				 },
				 "crowdsecurity/foobar_subparser": {
					"path": "parsers/s01-parse/crowdsecurity/foobar_subparser.yaml",
					"stage": "s01-parse",
					"version": "0.1",
					"versions": {
					 "0.1": {
					  "digest": "7d72765baa7227095d8e83803d81f2a8f383e5808f1a4d72deb425352afd59ae",
					  "deprecated": false
					 }
					},
					"long_description": "bG9uZyBkZXNjcmlwdGlvbgo=",
					"content": "bG9uZyBkZXNjcmlwdGlvbgo=",
					"description": "A foobar parser",
					"author": "crowdsecurity",
					"labels": null
				   }
				},
				"postoverflows": {
				},
				"scenarios": {
					"crowdsecurity/foobar_scenario": {
						"path": "scenarios/crowdsecurity/foobar_scenario.yaml",
						"version": "0.1",
						"versions": {
						 "0.1": {
						  "digest": "a76b389db944ca7a9e5a3f3ae61ee2d4ee98167164ec9b971174b1d44f5a01c6",
						  "deprecated": false
						 }
						},
						"long_description": "bG9uZyBkZXNjcmlwdGlvbgo=",
						"content": "bG9uZyBkZXNjcmlwdGlvbgo=",
						"description": "a foobar scenario",
						"author": "crowdsecurity",
						"labels": {
						 "remediation": "true",
						 "scope": "ip",
						 "service": "http",
						 "type": "web_attack"
						}
					   }
				}
			   }
			   `
	} else {
		log.Fatalf("unexpected url :/")
	}

	response.Body = ioutil.NopCloser(strings.NewReader(responseBody))
	return response, nil
}
