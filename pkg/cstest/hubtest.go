package cstest

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type HubTest struct {
	CrowdSecPath           string
	CscliPath              string
	HubPath                string
	HubTestPath            string
	HubIndexFile           string
	TemplateConfigPath     string
	TemplateProfilePath    string
	TemplateSimulationPath string
	Tests                  []HubTestItem
	Parallel               int
	TestDone               chan HubTestItem
}

const (
	templateConfigFile     = "template_config.yaml"
	templateSimulationFile = "template_simulation.yaml"
	templateProfileFile    = "template_profiles.yaml"
)

func NewHubTest(hubPath string, crowdsecPath string, cscliPath string) (HubTest, error) {
	var err error

	hubPath, err = filepath.Abs(hubPath)
	if err != nil {
		return HubTest{}, fmt.Errorf("can't get absolute path of hub: %+v", err)
	}
	// we can't use hubtest without the hub
	if _, err := os.Stat(hubPath); os.IsNotExist(err) {
		return HubTest{}, fmt.Errorf("path to hub '%s' doesn't exist, can't run", hubPath)
	}
	HubTestPath := filepath.Join(hubPath, "./.tests/")

	// we can't use hubtest without crowdsec binary
	if _, err := exec.LookPath(crowdsecPath); err != nil {
		if _, err := os.Stat(crowdsecPath); os.IsNotExist(err) {
			return HubTest{}, fmt.Errorf("path to crowdsec binary '%s' doesn't exist or is not in $PATH, can't run", crowdsecPath)
		}
	}

	// we can't use hubtest without cscli binary
	if _, err := exec.LookPath(cscliPath); err != nil {
		if _, err := os.Stat(cscliPath); os.IsNotExist(err) {
			return HubTest{}, fmt.Errorf("path to cscli binary '%s' doesn't exist or is not in $PATH, can't run", cscliPath)
		}
	}

	hubIndexFile := filepath.Join(hubPath, ".index.json")

	templateConfigFilePath := filepath.Join(HubTestPath, templateConfigFile)
	templateProfilePath := filepath.Join(HubTestPath, templateProfileFile)
	templateSimulationPath := filepath.Join(HubTestPath, templateSimulationFile)

	retHubTest := HubTest{
		CrowdSecPath:           crowdsecPath,
		CscliPath:              cscliPath,
		HubPath:                hubPath,
		HubTestPath:            HubTestPath,
		HubIndexFile:           hubIndexFile,
		TemplateConfigPath:     templateConfigFilePath,
		TemplateProfilePath:    templateProfilePath,
		TemplateSimulationPath: templateSimulationPath,
		TestDone:               make(chan HubTestItem),
		Parallel:               10,
	}

	return retHubTest, nil
}

func (h *HubTest) LoadTestItem(name string) (*HubTestItem, error) {
	HubTestItem := &HubTestItem{}
	testItem, err := NewTest(name, h)
	if err != nil {
		return HubTestItem, err
	}
	h.Tests = append(h.Tests, *testItem)

	return testItem, nil
}

func (h *HubTest) LoadAllTests() error {
	testsFolder, err := ioutil.ReadDir(h.HubTestPath)
	if err != nil {
		return err
	}

	for _, f := range testsFolder {
		if f.IsDir() {
			if _, err := h.LoadTestItem(f.Name()); err != nil {
				return errors.Wrapf(err, "while loading %s", f.Name())
			}
		}
	}
	return nil
}

func (h *HubTest) Run() error {
	runningTest := 0
	testCpt := 0
	toBreak := false
	for {
		select {
		case test := <-h.TestDone:
			if test.Success {
				log.Infof("Test '%s' successful", test.Name)
			} else {
				log.Infof("Test '%s' failed", test.Name)
			}
			runningTest--
		default:
			if runningTest < h.Parallel && testCpt < len(h.Tests) {
				log.Infof("Starting test '%s'", h.Tests[testCpt].Name)
				go h.Tests[testCpt].Run(h.TestDone)
				testCpt++
				runningTest++
			}
			if testCpt == len(h.Tests) && runningTest == 0 {
				log.Infof("Test are done, breaking")
				toBreak = true
				break
			}
			if runningTest == 0 {
				log.Infof("Running test '%d' | TestCpt: '%d/%d'", runningTest, testCpt, len(h.Tests))
			}
		}
		if toBreak {
			break
		}
	}

	return nil
}
