package hubtest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type HubTest struct {
	CrowdSecPath              string
	CscliPath                 string
	HubPath                   string
	HubTestPath               string //generic parser/scenario tests .tests
	HubAppsecTestPath         string //dir specific to appsec tests .appsec-tests
	HubIndexFile              string
	TemplateConfigPath        string
	TemplateProfilePath       string
	TemplateSimulationPath    string
	TemplateAcquisPath        string
	TemplateAppsecProfilePath string
	NucleiTargetHost          string
	AppSecHost                string

	HubIndex *cwhub.Hub
	Tests    []*HubTestItem
}

const (
	templateConfigFile        = "template_config.yaml"
	templateSimulationFile    = "template_simulation.yaml"
	templateProfileFile       = "template_profiles.yaml"
	templateAcquisFile        = "template_acquis.yaml"
	templateAppsecProfilePath = "template_appsec-profile.yaml"
	TemplateNucleiFile        = `id: {{.TestName}}
info:
  name: {{.TestName}}
  author: crowdsec
  severity: info
  description: {{.TestName}} testing
  tags: appsec-testing
http:
#this is a dummy request, edit the request(s) to match your needs
  - raw:
    - |
      GET /test HTTP/1.1
      Host: {{"{{"}}Hostname{{"}}"}}

    cookie-reuse: true
#test will fail because we won't match http status 
    matchers:
    - type: status
      status:
       - 403
`
)

func NewHubTest(hubPath string, crowdsecPath string, cscliPath string, isAppsecTest bool) (HubTest, error) {
	hubPath, err := filepath.Abs(hubPath)
	if err != nil {
		return HubTest{}, fmt.Errorf("can't get absolute path of hub: %+v", err)
	}

	// we can't use hubtest without the hub
	if _, err = os.Stat(hubPath); os.IsNotExist(err) {
		return HubTest{}, fmt.Errorf("path to hub '%s' doesn't exist, can't run", hubPath)
	}
	// we can't use hubtest without crowdsec binary
	if _, err = exec.LookPath(crowdsecPath); err != nil {
		if _, err = os.Stat(crowdsecPath); os.IsNotExist(err) {
			return HubTest{}, fmt.Errorf("path to crowdsec binary '%s' doesn't exist or is not in $PATH, can't run", crowdsecPath)
		}
	}

	// we can't use hubtest without cscli binary
	if _, err = exec.LookPath(cscliPath); err != nil {
		if _, err = os.Stat(cscliPath); os.IsNotExist(err) {
			return HubTest{}, fmt.Errorf("path to cscli binary '%s' doesn't exist or is not in $PATH, can't run", cscliPath)
		}
	}

	if isAppsecTest {
		HubTestPath := filepath.Join(hubPath, "./.appsec-tests/")
		hubIndexFile := filepath.Join(hubPath, ".index.json")

		local := &csconfig.LocalHubCfg{
			HubDir:         hubPath,
			HubIndexFile:   hubIndexFile,
			InstallDir:     HubTestPath,
			InstallDataDir: HubTestPath,
		}

		hub, err := cwhub.NewHub(local, nil, false, nil)
		if err != nil {
			return HubTest{}, fmt.Errorf("unable to load hub: %s", err)
		}

		return HubTest{
			CrowdSecPath:              crowdsecPath,
			CscliPath:                 cscliPath,
			HubPath:                   hubPath,
			HubTestPath:               HubTestPath,
			HubIndexFile:              hubIndexFile,
			TemplateConfigPath:        filepath.Join(HubTestPath, templateConfigFile),
			TemplateProfilePath:       filepath.Join(HubTestPath, templateProfileFile),
			TemplateSimulationPath:    filepath.Join(HubTestPath, templateSimulationFile),
			TemplateAppsecProfilePath: filepath.Join(HubTestPath, templateAppsecProfilePath),
			TemplateAcquisPath:        filepath.Join(HubTestPath, templateAcquisFile),
			NucleiTargetHost:          DefaultNucleiTarget,
			AppSecHost:                DefaultAppsecHost,
			HubIndex:                  hub,
		}, nil
	}

	HubTestPath := filepath.Join(hubPath, "./.tests/")

	hubIndexFile := filepath.Join(hubPath, ".index.json")

	local := &csconfig.LocalHubCfg{
		HubDir:         hubPath,
		HubIndexFile:   hubIndexFile,
		InstallDir:     HubTestPath,
		InstallDataDir: HubTestPath,
	}

	hub, err := cwhub.NewHub(local, nil, false, nil)
	if err != nil {
		return HubTest{}, fmt.Errorf("unable to load hub: %s", err)
	}

	return HubTest{
		CrowdSecPath:           crowdsecPath,
		CscliPath:              cscliPath,
		HubPath:                hubPath,
		HubTestPath:            HubTestPath,
		HubIndexFile:           hubIndexFile,
		TemplateConfigPath:     filepath.Join(HubTestPath, templateConfigFile),
		TemplateProfilePath:    filepath.Join(HubTestPath, templateProfileFile),
		TemplateSimulationPath: filepath.Join(HubTestPath, templateSimulationFile),
		HubIndex:               hub,
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
