package hubtest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type HubTest struct {
	CrowdSecPath              string
	CscliPath                 string
	HubPath                   string
	HubTestPath               string // generic parser/scenario tests .tests
	HubAppsecTestPath         string // dir specific to appsec tests .appsec-tests
	HubIndexFile              string
	TemplateConfigPath        string
	TemplateProfilePath       string
	TemplateSimulationPath    string
	TemplateAcquisPath        string
	TemplateAppsecProfilePath string
	NucleiTargetHost          string
	AppSecHost                string
	DataDir                   string // we share this one across tests, to avoid unnecessary downloads
	HubIndex                  *cwhub.Hub
	Tests                     []*HubTestItem
}

const (
	templateConfigFile        = "template_config2.yaml"
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

// resolveBinaryPath returns the absolute path to an executable.
// - If the `binary` argument is relative, it is resolved as absolute.
// - If it's not a path, it's looked up in $PATH.
// In all cases it returns an error if the file doesn’t exist (after following links) or is a directory.
func resolveBinaryPath(binary string) (string, error) {
	var resolved string

	switch {
	case filepath.IsAbs(binary):
		resolved = binary
	case strings.Contains(binary, string(os.PathSeparator)):
		absPath, err := filepath.Abs(binary)
		if err != nil {
			return "", err
		}
		resolved = absPath
	default:
		p, err := exec.LookPath(binary)
		if err != nil {
			return "", err
		}
		resolved = p
	}

	f, err := os.Stat(resolved)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", err
	case err != nil:
		return "", err
	}

	if f.IsDir() {
		return "", fmt.Errorf("%q is a directory, not a file", resolved)
	}

	return resolved, nil
}

func NewHubTest(hubPath string, crowdsecPath string, cscliPath string, isAppsecTest bool) (HubTest, error) {
	hubPath, err := filepath.Abs(hubPath)
	if err != nil {
		return HubTest{}, fmt.Errorf("can't get absolute path of hub: %w", err)
	}

	sharedDataDir := filepath.Join(hubPath, ".cache", "data")
	if err = os.MkdirAll(sharedDataDir, 0o700); err != nil {
		return HubTest{}, fmt.Errorf("while creating data dir: %w", err)
	}

	// we can't use hubtest without the hub
	if _, err = os.Stat(hubPath); os.IsNotExist(err) {
		return HubTest{}, fmt.Errorf("path to hub '%s' doesn't exist, can't run", hubPath)
	}
	// we can't use hubtest without crowdsec binary
	if crowdsecPath, err = resolveBinaryPath(crowdsecPath); err != nil {
		return HubTest{}, fmt.Errorf("can't find crowdsec binary: %w", err)
	}

	// we can't use hubtest without cscli binary
	if cscliPath, err = resolveBinaryPath(cscliPath); err != nil {
		return HubTest{}, fmt.Errorf("can't find cscli binary: %w", err)
	}

	if isAppsecTest {
		HubTestPath := filepath.Join(hubPath, ".appsec-tests")
		hubIndexFile := filepath.Join(hubPath, ".index.json")

		local := &csconfig.LocalHubCfg{
			HubDir:         hubPath,
			HubIndexFile:   hubIndexFile,
			InstallDir:     HubTestPath,
			InstallDataDir: sharedDataDir,
		}

		hub, err := cwhub.NewHub(local, nil)
		if err != nil {
			return HubTest{}, err
		}

		if err := hub.Load(); err != nil {
			return HubTest{}, err
		}

		return HubTest{
			CrowdSecPath:              crowdsecPath,
			CscliPath:                 cscliPath,
			DataDir:                   sharedDataDir,
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

	HubTestPath := filepath.Join(hubPath, ".tests")

	hubIndexFile := filepath.Join(hubPath, ".index.json")

	local := &csconfig.LocalHubCfg{
		HubDir:         hubPath,
		HubIndexFile:   hubIndexFile,
		InstallDir:     HubTestPath,
		InstallDataDir: sharedDataDir,
	}

	hub, err := cwhub.NewHub(local, nil)
	if err != nil {
		return HubTest{}, err
	}

	if err := hub.Load(); err != nil {
		return HubTest{}, err
	}

	return HubTest{
		CrowdSecPath:           crowdsecPath,
		CscliPath:              cscliPath,
		DataDir:                sharedDataDir,
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

	testItem, err := NewTest(name, h, h.DataDir)
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
