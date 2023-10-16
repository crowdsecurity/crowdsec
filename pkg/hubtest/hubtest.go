package hubtest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
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
	HubIndex               *cwhub.HubIndex
	Tests                  []*HubTestItem
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
	bidx, err := os.ReadFile(hubIndexFile)
	if err != nil {
		return HubTest{}, fmt.Errorf("unable to read index file: %s", err)
	}

	// load hub index
	hubIndex, err := cwhub.ParseIndex(bidx)
	if err != nil {
		return HubTest{}, fmt.Errorf("unable to load hub index file: %s", err)
	}

	templateConfigFilePath := filepath.Join(HubTestPath, templateConfigFile)
	templateProfilePath := filepath.Join(HubTestPath, templateProfileFile)
	templateSimulationPath := filepath.Join(HubTestPath, templateSimulationFile)

	return HubTest{
		CrowdSecPath:           crowdsecPath,
		CscliPath:              cscliPath,
		HubPath:                hubPath,
		HubTestPath:            HubTestPath,
		HubIndexFile:           hubIndexFile,
		TemplateConfigPath:     templateConfigFilePath,
		TemplateProfilePath:    templateProfilePath,
		TemplateSimulationPath: templateSimulationPath,
		HubIndex:               &cwhub.HubIndex{Items: hubIndex},
	}, nil
}

func (h *HubTest) LoadTestItem(name string) (*HubTestItem, error) {
	HubTestItem := &HubTestItem{}
	testItem, err := NewTest(name, h)
	if err != nil {
		return HubTestItem, err
	}
	h.Tests = append(h.Tests, testItem)

	return testItem, nil
}

func (h *HubTest) LoadAllTests() error {
	testsFolder, err := os.ReadDir(h.HubTestPath)
	if err != nil {
		return err
	}

	for _, f := range testsFolder {
		if f.IsDir() {
			if _, err := h.LoadTestItem(f.Name()); err != nil {
				return fmt.Errorf("while loading %s: %w", f.Name(), err)
			}
		}
	}
	return nil
}
