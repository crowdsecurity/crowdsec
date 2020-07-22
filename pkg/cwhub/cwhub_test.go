package cwhub

import (
	"os"
	"path/filepath"
	"testing"

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

	os.RemoveAll(Cfgdir)
	test_prepenv()

	_, err := DownloadHubIdx()
	if err != nil {
		t.Fatalf("failed to download index")
	}
	if err := GetHubIdx(); err != nil {
		t.Fatalf("failed to load hub index")
	}
}

func test_prepenv() {
	// 	var Installdir = "/etc/crowdsec/"
	// var Hubdir = "/etc/crowdsec/cscli/hub/"
	// var Cfgdir = "/etc/crowdsec/cscli/"
	log.SetLevel(log.DebugLevel)

	Cfgdir = filepath.Clean("./cscli")
	Installdir = filepath.Clean("./install")
	Hubdir = filepath.Clean("./hubdir")
	//Datadir := "./data"

	if _, err := os.Stat("./cscli/.index.json"); os.IsNotExist(err) {
		os.MkdirAll(Cfgdir, 0700)
		err := UpdateHubIdx()
		if err != nil {
			log.Fatalf("failed to download index")
		}
	}

	os.RemoveAll(Installdir)
	os.MkdirAll(Installdir, 0700)
	os.RemoveAll(Hubdir)
	os.MkdirAll(Hubdir, 0700)
}

func testInstallItem(t *testing.T, item Item) {
	//Install the parser
	item, err := DownloadLatest(item, Hubdir, false, testDataFolder)
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

	item, err = EnableItem(item, Installdir, Hubdir)
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
	item, err := DownloadLatest(item, Hubdir, true, testDataFolder)
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
	item, err := DisableItem(item, Installdir, Hubdir, false)
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
