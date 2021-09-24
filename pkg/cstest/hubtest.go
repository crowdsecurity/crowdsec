package cstest

import (
	"io/ioutil"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type HubTest struct {
	HubPath                string
	HubTestPath            string
	HubIndexFile           string
	TemplateConfigPath     string
	TemplateProfilePath    string
	TemplateSimulationPath string
	HubIndex               *HubIndex
	Tests                  []*HubTestItem
}

const (
	templateConfigFile     = "template_config.yaml"
	templateSimulationFile = "template_simulation.yaml"
	templateProfileFile    = "template_profiles.yaml"
	parserAssertFileName   = "parser.assert"
	parserResultFileName   = "parser-dump.yaml"
	crowdsecPatternsFolder = "/etc/crowdsec/patterns/"
)

func NewHubTest(hubPath string) (HubTest, error) {
	var err error

	hubPath, err = filepath.Abs(hubPath)
	if err != nil {
		log.Fatalf("can't get absolute path of hub: %+v", err)
	}

	// we can't use this command without the hub
	if _, err := os.Stat(hubPath); os.IsNotExist(err) {
		log.Fatalf("path to hub doesn't exist, can't run: %+v", err)
	}
	HubTestPath := filepath.Join(hubPath, "./.tests/")

	hubIndexFile := filepath.Join(hubPath, ".index.json")
	bidx, err := ioutil.ReadFile(hubIndexFile)
	if err != nil {
		log.Fatalf("unable to read index file: %s", err)
	}

	// load hub index
	hubIndex, err := cwhub.LoadPkgIndex(bidx)
	if err != nil {
		log.Fatalf("unable to load hub index file: %s", err)
	}

	templateConfigFilePath := filepath.Join(HubTestPath, templateConfigFile)
	templateProfilePath := filepath.Join(HubTestPath, templateProfileFile)
	templateSimulationPath := filepath.Join(HubTestPath, templateSimulationFile)

	return HubTest{
		HubPath:                hubPath,
		HubTestPath:            HubTestPath,
		HubIndexFile:           hubIndexFile,
		TemplateConfigPath:     templateConfigFilePath,
		TemplateProfilePath:    templateProfilePath,
		TemplateSimulationPath: templateSimulationPath,
		HubIndex:               &HubIndex{Data: hubIndex},
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
