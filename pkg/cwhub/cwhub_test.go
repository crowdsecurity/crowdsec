package cwhub

import (
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

var testDataFolder = "."

func TestIndexDownload(t *testing.T) {

	if csconfig.GConfig == nil {
		csconfig.GConfig = csconfig.NewDefaultConfig()
	}
	if csconfig.GConfig.Crowdsec != nil {
		os.RemoveAll(csconfig.GConfig.Crowdsec.ConfigDir)
	}
	if csconfig.GConfig.Cscli != nil {
		os.RemoveAll(csconfig.GConfig.Cscli.HubDir)
	}
	test_prepenv()

	err := UpdateHubIdx()
	//DownloadHubIdx()
	if err != nil {
		t.Fatalf("failed to download index : %s", err)
	}
	if err := GetHubIdx(); err != nil {
		t.Fatalf("failed to load hub index : %s", err)
	}
}

func test_prepenv() {
	log.SetLevel(log.DebugLevel)

	if csconfig.GConfig == nil {
		csconfig.GConfig = csconfig.NewDefaultConfig()
	}

	csconfig.GConfig.Crowdsec.ConfigDir = filepath.Clean("./install")
	csconfig.GConfig.Cscli.HubDir = filepath.Clean("./hubdir")
	csconfig.GConfig.Cscli.IndexPath = filepath.Clean("./hubdir/.index.json")

	//Mock the http client
	http.DefaultClient.Transport = newMockTransport()

	if err := os.RemoveAll(csconfig.GConfig.Crowdsec.ConfigDir); err != nil {
		log.Fatalf("failed to remove %s : %s", csconfig.GConfig.Crowdsec.ConfigDir, err)
	}

	if err := os.MkdirAll(csconfig.GConfig.Crowdsec.ConfigDir, 0700); err != nil {
		log.Fatalf("mkdir : %s", err)
	}

	if err := os.RemoveAll(csconfig.GConfig.Cscli.HubDir); err != nil {
		log.Fatalf("failed to remove %s : %s", csconfig.GConfig.Cscli.HubDir, err)
	}
	if err := os.MkdirAll(csconfig.GConfig.Cscli.HubDir, 0700); err != nil {
		log.Fatalf("failed to mkdir %s : %s", csconfig.GConfig.Cscli.HubDir, err)
	}

	if err := UpdateHubIdx(); err != nil {
		log.Fatalf("failed to download index : %s", err)
	}

	// if err := os.RemoveAll(csconfig.GConfig.Crowdsec.ConfigDir); err != nil {
	// 	log.Fatalf("failed to remove %s : %s", csconfig.GConfig.Crowdsec.ConfigDir, err)
	// }
	// if err := os.MkdirAll(csconfig.GConfig.Crowdsec.ConfigDir, 0700); err != nil {
	// 	log.Fatalf("failed to mkdir %s : %s", csconfig.GConfig.Crowdsec.ConfigDir, err)
	// }

}

func testInstallItem(t *testing.T, item Item) {
	//Install the parser
	item, err := DownloadLatest(item, csconfig.GConfig.Cscli.HubDir, false, testDataFolder)
	if err != nil {
		t.Fatalf("error while downloading %s : %v", item.Name, err)
	}
	if err := LocalSync(); err != nil {
		t.Fatalf("taint: failed to run localSync : %s", err)
	}
	if !HubIdx[item.Type][item.Name].UpToDate {
		t.Fatalf("download: %s should be up-to-date", item.Name)
	}
	if HubIdx[item.Type][item.Name].Installed {
		t.Fatalf("download: %s should not be install", item.Name)
	}
	if HubIdx[item.Type][item.Name].Tainted {
		t.Fatalf("download: %s should not be tainted", item.Name)
	}

	item, err = EnableItem(item, csconfig.GConfig.Crowdsec.ConfigDir, csconfig.GConfig.Cscli.HubDir)
	if err != nil {
		t.Fatalf("error while enabled %s : %v.", item.Name, err)
	}
	if err := LocalSync(); err != nil {
		t.Fatalf("taint: failed to run localSync : %s", err)
	}
	if !HubIdx[item.Type][item.Name].Installed {
		t.Fatalf("install: %s should be install", item.Name)
	}
}

func testTaintItem(t *testing.T, item Item) {
	if HubIdx[item.Type][item.Name].Tainted {
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
	if err := LocalSync(); err != nil {
		t.Fatalf("taint: failed to run localSync : %s", err)
	}
	if !HubIdx[item.Type][item.Name].Tainted {
		t.Fatalf("taint: %s should be tainted", item.Name)
	}
}

func testUpdateItem(t *testing.T, item Item) {

	if HubIdx[item.Type][item.Name].UpToDate {
		t.Fatalf("update: %s should NOT be up-to-date", item.Name)
	}
	//Update it + check status
	item, err := DownloadLatest(item, csconfig.GConfig.Cscli.HubDir, true, testDataFolder)
	if err != nil {
		t.Fatalf("failed to update %s : %s", item.Name, err)
	}
	//Local sync and check status
	if err := LocalSync(); err != nil {
		t.Fatalf("failed to run localSync : %s", err)
	}
	if !HubIdx[item.Type][item.Name].UpToDate {
		t.Fatalf("update: %s should be up-to-date", item.Name)
	}
	if HubIdx[item.Type][item.Name].Tainted {
		t.Fatalf("update: %s should not be tainted anymore", item.Name)
	}
}

func testDisableItem(t *testing.T, item Item) {
	if !item.Installed {
		t.Fatalf("disable: %s should be installed", item.Name)
	}
	//Remove
	item, err := DisableItem(item, csconfig.GConfig.Crowdsec.ConfigDir, csconfig.GConfig.Cscli.HubDir, false)
	if err != nil {
		t.Fatalf("failed to disable item : %v", err)
	}
	//Local sync and check status
	if err := LocalSync(); err != nil {
		t.Fatalf("failed to run localSync : %s", err)
	}
	if HubIdx[item.Type][item.Name].Tainted {
		t.Fatalf("disable: %s should not be tainted anymore", item.Name)
	}
	if HubIdx[item.Type][item.Name].Installed {
		t.Fatalf("disable: %s should not be installed anymore", item.Name)
	}
	if !HubIdx[item.Type][item.Name].Downloaded {
		t.Fatalf("disable: %s should still be downloaded", item.Name)
	}
	//Purge
	item, err = DisableItem(item, csconfig.GConfig.Crowdsec.ConfigDir, csconfig.GConfig.Cscli.HubDir, true)
	if err != nil {
		t.Fatalf("failed to purge item : %v", err)
	}
	//Local sync and check status
	if err := LocalSync(); err != nil {
		t.Fatalf("failed to run localSync : %s", err)
	}
	if HubIdx[item.Type][item.Name].Installed {
		t.Fatalf("disable: %s should not be installed anymore", item.Name)
	}
	if HubIdx[item.Type][item.Name].Downloaded {
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
	test_prepenv()

	if err := GetHubIdx(); err != nil {
		t.Fatalf("failed to load hub index")
	}
	//map iteration is random by itself
	for _, it := range HubIdx[PARSERS] {
		testInstallItem(t, it)
		it = HubIdx[PARSERS][it.Name]
		_ = HubStatus(PARSERS, it.Name, false)
		testTaintItem(t, it)
		it = HubIdx[PARSERS][it.Name]
		_ = HubStatus(PARSERS, it.Name, false)
		testUpdateItem(t, it)
		it = HubIdx[PARSERS][it.Name]
		testDisableItem(t, it)
		it = HubIdx[PARSERS][it.Name]

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
	test_prepenv()

	if err := GetHubIdx(); err != nil {
		t.Fatalf("failed to load hub index")
	}
	//map iteration is random by itself
	for _, it := range HubIdx[COLLECTIONS] {
		testInstallItem(t, it)
		it = HubIdx[COLLECTIONS][it.Name]
		testTaintItem(t, it)
		it = HubIdx[COLLECTIONS][it.Name]
		testUpdateItem(t, it)
		it = HubIdx[COLLECTIONS][it.Name]
		testDisableItem(t, it)
		it = HubIdx[COLLECTIONS][it.Name]
		x := HubStatus(COLLECTIONS, it.Name, false)
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
	if req.URL.Path == "/crowdsecurity/hub/master/parsers/s01-parse/crowdsecurity/foobar_parser.yaml" {
		responseBody = `onsuccess: next_stage
filter: evt.Parsed.program == 'foobar_parser'
name: crowdsecurity/foobar_parser
#debug: true
description: A parser for foobar_parser WAF
grok:
  name: foobar_parser
  apply_on: message
`

	} else if req.URL.Path == "/crowdsecurity/hub/master/parsers/s01-parse/crowdsecurity/foobar_subparser.yaml" {
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

	} else if req.URL.Path == "/crowdsecurity/hub/master/scenarios/crowdsecurity/foobar_scenario.yaml" {
		responseBody = `filter: true
name: crowdsecurity/foobar_scenario`
		/*FAKE COLLECTIONS*/
	} else if req.URL.Path == "/crowdsecurity/hub/master/collections/crowdsecurity/foobar.yaml" {
		responseBody = `
blah: blalala
qwe: jejwejejw`
	} else if req.URL.Path == "/crowdsecurity/hub/master/collections/crowdsecurity/foobar_subcollection.yaml" {
		responseBody = `
blah: blalala
qwe: jejwejejw`
	} else if req.URL.Path == "/crowdsecurity/hub/master/.index.json" {
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
