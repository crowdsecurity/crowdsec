package hubtest

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
)

type HubTestItemConfig struct {
	Parsers               []string            `yaml:"parsers,omitempty"`
	Scenarios             []string            `yaml:"scenarios,omitempty"`
	PostOverflows         []string            `yaml:"postoverflows,omitempty"`
	AppsecRules           []string            `yaml:"appsec-rules,omitempty"`
	NucleiTemplate        string              `yaml:"nuclei_template,omitempty"`
	ExpectedNucleiFailure bool                `yaml:"expect_failure,omitempty"`
	LogFile               string              `yaml:"log_file,omitempty"`
	LogType               string              `yaml:"log_type,omitempty"`
	Labels                map[string]string   `yaml:"labels,omitempty"`
	IgnoreParsers         bool                `yaml:"ignore_parsers,omitempty"`   // if we test a scenario, we don't want to assert on Parser
	OverrideStatics       []parser.ExtraField `yaml:"override_statics,omitempty"` //Allow to override statics. Executed before s00
}

type HubTestItem struct {
	Name string
	Path string

	CrowdSecPath string
	CscliPath    string

	RuntimePath               string
	RuntimeHubPath            string
	RuntimeDataPath           string
	RuntimePatternsPath       string
	RuntimeConfigFilePath     string
	RuntimeProfileFilePath    string
	RuntimeSimulationFilePath string
	RuntimeAcquisFilePath     string
	RuntimeHubConfig          *csconfig.LocalHubCfg

	ResultsPath          string
	ParserResultFile     string
	ScenarioResultFile   string
	BucketPourResultFile string

	HubPath                   string
	HubTestPath               string
	HubIndexFile              string
	TemplateConfigPath        string
	TemplateProfilePath       string
	TemplateSimulationPath    string
	TemplateAcquisPath        string
	TemplateAppsecProfilePath string
	HubIndex                  *cwhub.Hub

	Config *HubTestItemConfig

	Success    bool
	ErrorsList []string

	AutoGen        bool
	ParserAssert   *ParserAssert
	ScenarioAssert *ScenarioAssert

	CustomItemsLocation []string

	NucleiTargetHost string
	AppSecHost       string
}

const (
	ParserAssertFileName = "parser.assert"
	ParserResultFileName = "parser-dump.yaml"

	ScenarioAssertFileName = "scenario.assert"
	ScenarioResultFileName = "bucket-dump.yaml"

	BucketPourResultFileName = "bucketpour-dump.yaml"

	TestBouncerApiKey = "this_is_a_bad_password"

	DefaultNucleiTarget = "http://127.0.0.1:7822/"
	DefaultAppsecHost   = "127.0.0.1:4241"
)

func NewTest(name string, hubTest *HubTest) (*HubTestItem, error) {
	testPath := filepath.Join(hubTest.HubTestPath, name)
	runtimeFolder := filepath.Join(testPath, "runtime")
	runtimeHubFolder := filepath.Join(runtimeFolder, "hub")
	configFilePath := filepath.Join(testPath, "config.yaml")
	resultPath := filepath.Join(testPath, "results")

	// read test configuration file
	configFileData := &HubTestItemConfig{}

	yamlFile, err := os.ReadFile(configFilePath)
	if err != nil {
		log.Printf("no config file found in '%s': %v", testPath, err)
	}

	err = yaml.Unmarshal(yamlFile, configFileData)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %v", err)
	}

	parserAssertFilePath := filepath.Join(testPath, ParserAssertFileName)
	ParserAssert := NewParserAssert(parserAssertFilePath)

	scenarioAssertFilePath := filepath.Join(testPath, ScenarioAssertFileName)
	ScenarioAssert := NewScenarioAssert(scenarioAssertFilePath)

	return &HubTestItem{
		Name:                      name,
		Path:                      testPath,
		CrowdSecPath:              hubTest.CrowdSecPath,
		CscliPath:                 hubTest.CscliPath,
		RuntimePath:               filepath.Join(testPath, "runtime"),
		RuntimeHubPath:            runtimeHubFolder,
		RuntimeDataPath:           filepath.Join(runtimeFolder, "data"),
		RuntimePatternsPath:       filepath.Join(runtimeFolder, "patterns"),
		RuntimeConfigFilePath:     filepath.Join(runtimeFolder, "config.yaml"),
		RuntimeProfileFilePath:    filepath.Join(runtimeFolder, "profiles.yaml"),
		RuntimeSimulationFilePath: filepath.Join(runtimeFolder, "simulation.yaml"),
		RuntimeAcquisFilePath:     filepath.Join(runtimeFolder, "acquis.yaml"),
		ResultsPath:               resultPath,
		ParserResultFile:          filepath.Join(resultPath, ParserResultFileName),
		ScenarioResultFile:        filepath.Join(resultPath, ScenarioResultFileName),
		BucketPourResultFile:      filepath.Join(resultPath, BucketPourResultFileName),
		RuntimeHubConfig: &csconfig.LocalHubCfg{
			HubDir:         runtimeHubFolder,
			HubIndexFile:   hubTest.HubIndexFile,
			InstallDir:     runtimeFolder,
			InstallDataDir: filepath.Join(runtimeFolder, "data"),
		},
		Config:                    configFileData,
		HubPath:                   hubTest.HubPath,
		HubTestPath:               hubTest.HubTestPath,
		HubIndexFile:              hubTest.HubIndexFile,
		TemplateConfigPath:        hubTest.TemplateConfigPath,
		TemplateProfilePath:       hubTest.TemplateProfilePath,
		TemplateSimulationPath:    hubTest.TemplateSimulationPath,
		TemplateAcquisPath:        hubTest.TemplateAcquisPath,
		TemplateAppsecProfilePath: hubTest.TemplateAppsecProfilePath,
		HubIndex:                  hubTest.HubIndex,
		ScenarioAssert:            ScenarioAssert,
		ParserAssert:              ParserAssert,
		CustomItemsLocation:       []string{hubTest.HubPath, testPath},
		NucleiTargetHost:          hubTest.NucleiTargetHost,
		AppSecHost:                hubTest.AppSecHost,
	}, nil
}

func (t *HubTestItem) installHubItems(names []string, installFunc func(string) error) error {
	for _, name := range names {
		if name == "" {
			continue
		}

		if err := installFunc(name); err != nil {
			return err
		}
	}

	return nil
}

func (t *HubTestItem) InstallHub() error {
	if err := t.installHubItems(t.Config.Parsers, t.installParser); err != nil {
		return err
	}

	if err := t.installHubItems(t.Config.Scenarios, t.installScenario); err != nil {
		return err
	}

	if err := t.installHubItems(t.Config.PostOverflows, t.installPostoverflow); err != nil {
		return err
	}

	if err := t.installHubItems(t.Config.AppsecRules, t.installAppsecRule); err != nil {
		return err
	}

	if len(t.Config.OverrideStatics) > 0 {
		n := parser.Node{
			Name:    "overrides",
			Filter:  "1==1",
			Statics: t.Config.OverrideStatics,
		}

		b, err := yaml.Marshal(n)
		if err != nil {
			return fmt.Errorf("unable to marshal overrides: %s", err)
		}

		tgtFilename := fmt.Sprintf("%s/parsers/s00-raw/00_overrides.yaml", t.RuntimePath)
		if err := os.WriteFile(tgtFilename, b, os.ModePerm); err != nil {
			return fmt.Errorf("unable to write overrides to '%s': %s", tgtFilename, err)
		}
	}

	// load installed hub
	hub, err := cwhub.NewHub(t.RuntimeHubConfig, nil, false, nil)
	if err != nil {
		log.Fatal(err)
	}

	// install data for parsers if needed
	ret := hub.GetItemMap(cwhub.PARSERS)
	for parserName, item := range ret {
		if item.State.Installed {
			if err := item.DownloadDataIfNeeded(true); err != nil {
				return fmt.Errorf("unable to download data for parser '%s': %+v", parserName, err)
			}

			log.Debugf("parser '%s' installed successfully in runtime environment", parserName)
		}
	}

	// install data for scenarios if needed
	ret = hub.GetItemMap(cwhub.SCENARIOS)
	for scenarioName, item := range ret {
		if item.State.Installed {
			if err := item.DownloadDataIfNeeded(true); err != nil {
				return fmt.Errorf("unable to download data for parser '%s': %+v", scenarioName, err)
			}

			log.Debugf("scenario '%s' installed successfully in runtime environment", scenarioName)
		}
	}

	// install data for postoverflows if needed
	ret = hub.GetItemMap(cwhub.POSTOVERFLOWS)
	for postoverflowName, item := range ret {
		if item.State.Installed {
			if err := item.DownloadDataIfNeeded(true); err != nil {
				return fmt.Errorf("unable to download data for parser '%s': %+v", postoverflowName, err)
			}

			log.Debugf("postoverflow '%s' installed successfully in runtime environment", postoverflowName)
		}
	}

	return nil
}

func (t *HubTestItem) Clean() error {
	return os.RemoveAll(t.RuntimePath)
}

func (t *HubTestItem) RunWithNucleiTemplate() error {
	crowdsecLogFile := fmt.Sprintf("%s/log/crowdsec.log", t.RuntimePath)

	testPath := filepath.Join(t.HubTestPath, t.Name)
	if _, err := os.Stat(testPath); os.IsNotExist(err) {
		return fmt.Errorf("test '%s' doesn't exist in '%s', exiting", t.Name, t.HubTestPath)
	}

	if err := os.Chdir(testPath); err != nil {
		return fmt.Errorf("can't 'cd' to '%s': %s", testPath, err)
	}

	//machine add
	cmdArgs := []string{"-c", t.RuntimeConfigFilePath, "machines", "add", "testMachine", "--force", "--auto"}
	cscliRegisterCmd := exec.Command(t.CscliPath, cmdArgs...)

	output, err := cscliRegisterCmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(string(output), "unable to create machine: user 'testMachine': user already exist") {
			fmt.Println(string(output))
			return fmt.Errorf("fail to run '%s' for test '%s': %v", cscliRegisterCmd.String(), t.Name, err)
		}
	}

	//hardcode bouncer key
	cmdArgs = []string{"-c", t.RuntimeConfigFilePath, "bouncers", "add", "appsectests", "-k", TestBouncerApiKey}
	cscliBouncerCmd := exec.Command(t.CscliPath, cmdArgs...)

	output, err = cscliBouncerCmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(string(output), "unable to create bouncer: bouncer appsectests already exists") {
			fmt.Println(string(output))
			return fmt.Errorf("fail to run '%s' for test '%s': %v", cscliRegisterCmd.String(), t.Name, err)
		}
	}

	//start crowdsec service
	cmdArgs = []string{"-c", t.RuntimeConfigFilePath}
	crowdsecDaemon := exec.Command(t.CrowdSecPath, cmdArgs...)

	crowdsecDaemon.Start()

	//wait for the appsec port to be available
	if _, err := IsAlive(t.AppSecHost); err != nil {
		crowdsecLog, err2 := os.ReadFile(crowdsecLogFile)
		if err2 != nil {
			log.Errorf("unable to read crowdsec log file '%s': %s", crowdsecLogFile, err)
		} else {
			log.Errorf("crowdsec log file '%s'", crowdsecLogFile)
			log.Errorf("%s\n", string(crowdsecLog))
		}

		return fmt.Errorf("appsec is down: %s", err)
	}

	// check if the target is available
	nucleiTargetParsedURL, err := url.Parse(t.NucleiTargetHost)
	if err != nil {
		return fmt.Errorf("unable to parse target '%s': %s", t.NucleiTargetHost, err)
	}

	nucleiTargetHost := nucleiTargetParsedURL.Host
	if _, err := IsAlive(nucleiTargetHost); err != nil {
		return fmt.Errorf("target is down: %s", err)
	}

	nucleiConfig := NucleiConfig{
		Path:      "nuclei",
		OutputDir: t.RuntimePath,
		CmdLineOptions: []string{"-ev", //allow variables from environment
			"-nc",    //no colors in output
			"-dresp", //dump response
			"-j",     //json output
		},
	}

	err = nucleiConfig.RunNucleiTemplate(t.Name, t.Config.NucleiTemplate, t.NucleiTargetHost)
	if t.Config.ExpectedNucleiFailure {
		if err != nil && errors.Is(err, ErrNucleiTemplateFail) {
			log.Infof("Appsec test %s failed as expected", t.Name)
			t.Success = true
		} else {
			log.Errorf("Appsec test %s failed:  %s", t.Name, err)
			crowdsecLog, err := os.ReadFile(crowdsecLogFile)
			if err != nil {
				log.Errorf("unable to read crowdsec log file '%s': %s", crowdsecLogFile, err)
			} else {
				log.Errorf("crowdsec log file '%s'", crowdsecLogFile)
				log.Errorf("%s\n", string(crowdsecLog))
			}
		}
	} else {
		if err == nil {
			log.Infof("Appsec test %s succeeded", t.Name)
			t.Success = true
		} else {
			log.Errorf("Appsec test %s failed:  %s", t.Name, err)
			crowdsecLog, err := os.ReadFile(crowdsecLogFile)
			if err != nil {
				log.Errorf("unable to read crowdsec log file '%s': %s", crowdsecLogFile, err)
			} else {
				log.Errorf("crowdsec log file '%s'", crowdsecLogFile)
				log.Errorf("%s\n", string(crowdsecLog))
			}
		}
	}

	crowdsecDaemon.Process.Kill()

	return nil
}

func (t *HubTestItem) RunWithLogFile() error {
	testPath := filepath.Join(t.HubTestPath, t.Name)
	if _, err := os.Stat(testPath); os.IsNotExist(err) {
		return fmt.Errorf("test '%s' doesn't exist in '%s', exiting", t.Name, t.HubTestPath)
	}

	currentDir, err := os.Getwd() //xx
	if err != nil {
		return fmt.Errorf("can't get current directory: %+v", err)
	}

	// create runtime folder
	if err = os.MkdirAll(t.RuntimePath, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.RuntimePath, err)
	}

	// create runtime data folder
	if err = os.MkdirAll(t.RuntimeDataPath, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.RuntimeDataPath, err)
	}

	// create runtime hub folder
	if err = os.MkdirAll(t.RuntimeHubPath, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.RuntimeHubPath, err)
	}

	if err = Copy(t.HubIndexFile, filepath.Join(t.RuntimeHubPath, ".index.json")); err != nil {
		return fmt.Errorf("unable to copy .index.json file in '%s': %s", filepath.Join(t.RuntimeHubPath, ".index.json"), err)
	}

	// create results folder
	if err = os.MkdirAll(t.ResultsPath, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.ResultsPath, err)
	}

	// copy template config file to runtime folder
	if err = Copy(t.TemplateConfigPath, t.RuntimeConfigFilePath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %v", t.TemplateConfigPath, t.RuntimeConfigFilePath, err)
	}

	// copy template profile file to runtime folder
	if err = Copy(t.TemplateProfilePath, t.RuntimeProfileFilePath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %v", t.TemplateProfilePath, t.RuntimeProfileFilePath, err)
	}

	// copy template simulation file to runtime folder
	if err = Copy(t.TemplateSimulationPath, t.RuntimeSimulationFilePath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %v", t.TemplateSimulationPath, t.RuntimeSimulationFilePath, err)
	}

	crowdsecPatternsFolder := csconfig.DefaultConfigPath("patterns")

	// copy template patterns folder to runtime folder
	if err = CopyDir(crowdsecPatternsFolder, t.RuntimePatternsPath); err != nil {
		return fmt.Errorf("unable to copy 'patterns' from '%s' to '%s': %s", crowdsecPatternsFolder, t.RuntimePatternsPath, err)
	}

	// install the hub in the runtime folder
	if err = t.InstallHub(); err != nil {
		return fmt.Errorf("unable to install hub in '%s': %s", t.RuntimeHubPath, err)
	}

	logFile := t.Config.LogFile
	logType := t.Config.LogType
	dsn := fmt.Sprintf("file://%s", logFile)

	if err = os.Chdir(testPath); err != nil {
		return fmt.Errorf("can't 'cd' to '%s': %s", testPath, err)
	}

	logFileStat, err := os.Stat(logFile)
	if err != nil {
		return fmt.Errorf("unable to stat log file '%s': %s", logFile, err)
	}

	if logFileStat.Size() == 0 {
		return fmt.Errorf("log file '%s' is empty, please fill it with log", logFile)
	}

	cmdArgs := []string{"-c", t.RuntimeConfigFilePath, "machines", "add", "testMachine", "--force", "--auto"}
	cscliRegisterCmd := exec.Command(t.CscliPath, cmdArgs...)
	log.Debugf("%s", cscliRegisterCmd.String())

	output, err := cscliRegisterCmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(string(output), "unable to create machine: user 'testMachine': user already exist") {
			fmt.Println(string(output))
			return fmt.Errorf("fail to run '%s' for test '%s': %v", cscliRegisterCmd.String(), t.Name, err)
		}
	}

	cmdArgs = []string{"-c", t.RuntimeConfigFilePath, "-type", logType, "-dsn", dsn, "-dump-data", t.ResultsPath, "-order-event"}

	for labelKey, labelValue := range t.Config.Labels {
		arg := fmt.Sprintf("%s:%s", labelKey, labelValue)
		cmdArgs = append(cmdArgs, "-label", arg)
	}

	crowdsecCmd := exec.Command(t.CrowdSecPath, cmdArgs...)
	log.Debugf("%s", crowdsecCmd.String())
	output, err = crowdsecCmd.CombinedOutput()

	if log.GetLevel() >= log.DebugLevel || err != nil {
		fmt.Println(string(output))
	}

	if err != nil {
		return fmt.Errorf("fail to run '%s' for test '%s': %v", crowdsecCmd.String(), t.Name, err)
	}

	if err := os.Chdir(currentDir); err != nil {
		return fmt.Errorf("can't 'cd' to '%s': %s", currentDir, err)
	}

	// assert parsers
	if !t.Config.IgnoreParsers {
		_, err := os.Stat(t.ParserAssert.File)
		if os.IsNotExist(err) {
			parserAssertFile, err := os.Create(t.ParserAssert.File)
			if err != nil {
				return err
			}

			parserAssertFile.Close()
		}

		assertFileStat, err := os.Stat(t.ParserAssert.File)
		if err != nil {
			return fmt.Errorf("error while stats '%s': %s", t.ParserAssert.File, err)
		}

		if assertFileStat.Size() == 0 {
			assertData, err := t.ParserAssert.AutoGenFromFile(t.ParserResultFile)
			if err != nil {
				return fmt.Errorf("couldn't generate assertion: %s", err)
			}

			t.ParserAssert.AutoGenAssertData = assertData
			t.ParserAssert.AutoGenAssert = true
		} else {
			if err := t.ParserAssert.AssertFile(t.ParserResultFile); err != nil {
				return fmt.Errorf("unable to run assertion on file '%s': %s", t.ParserResultFile, err)
			}
		}
	}

	// assert scenarios
	nbScenario := 0

	for _, scenario := range t.Config.Scenarios {
		if scenario == "" {
			continue
		}

		nbScenario++
	}

	if nbScenario > 0 {
		_, err := os.Stat(t.ScenarioAssert.File)
		if os.IsNotExist(err) {
			scenarioAssertFile, err := os.Create(t.ScenarioAssert.File)
			if err != nil {
				return err
			}

			scenarioAssertFile.Close()
		}

		assertFileStat, err := os.Stat(t.ScenarioAssert.File)
		if err != nil {
			return fmt.Errorf("error while stats '%s': %s", t.ScenarioAssert.File, err)
		}

		if assertFileStat.Size() == 0 {
			assertData, err := t.ScenarioAssert.AutoGenFromFile(t.ScenarioResultFile)
			if err != nil {
				return fmt.Errorf("couldn't generate assertion: %s", err)
			}

			t.ScenarioAssert.AutoGenAssertData = assertData
			t.ScenarioAssert.AutoGenAssert = true
		} else {
			if err := t.ScenarioAssert.AssertFile(t.ScenarioResultFile); err != nil {
				return fmt.Errorf("unable to run assertion on file '%s': %s", t.ScenarioResultFile, err)
			}
		}
	}

	if t.ParserAssert.AutoGenAssert || t.ScenarioAssert.AutoGenAssert {
		t.AutoGen = true
	}

	if (t.ParserAssert.Success || t.Config.IgnoreParsers) && (nbScenario == 0 || t.ScenarioAssert.Success) {
		t.Success = true
	}

	return nil
}

func (t *HubTestItem) Run() error {
	var err error

	t.Success = false
	t.ErrorsList = make([]string, 0)

	// create runtime folder
	if err = os.MkdirAll(t.RuntimePath, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.RuntimePath, err)
	}

	// create runtime data folder
	if err = os.MkdirAll(t.RuntimeDataPath, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.RuntimeDataPath, err)
	}

	// create runtime hub folder
	if err = os.MkdirAll(t.RuntimeHubPath, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.RuntimeHubPath, err)
	}

	if err = Copy(t.HubIndexFile, filepath.Join(t.RuntimeHubPath, ".index.json")); err != nil {
		return fmt.Errorf("unable to copy .index.json file in '%s': %s", filepath.Join(t.RuntimeHubPath, ".index.json"), err)
	}

	// create results folder
	if err = os.MkdirAll(t.ResultsPath, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.ResultsPath, err)
	}

	// copy template config file to runtime folder
	if err = Copy(t.TemplateConfigPath, t.RuntimeConfigFilePath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %v", t.TemplateConfigPath, t.RuntimeConfigFilePath, err)
	}

	// copy template profile file to runtime folder
	if err = Copy(t.TemplateProfilePath, t.RuntimeProfileFilePath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %v", t.TemplateProfilePath, t.RuntimeProfileFilePath, err)
	}

	// copy template simulation file to runtime folder
	if err = Copy(t.TemplateSimulationPath, t.RuntimeSimulationFilePath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %v", t.TemplateSimulationPath, t.RuntimeSimulationFilePath, err)
	}

	crowdsecPatternsFolder := csconfig.DefaultConfigPath("patterns")

	// copy template patterns folder to runtime folder
	if err = CopyDir(crowdsecPatternsFolder, t.RuntimePatternsPath); err != nil {
		return fmt.Errorf("unable to copy 'patterns' from '%s' to '%s': %s", crowdsecPatternsFolder, t.RuntimePatternsPath, err)
	}

	// create the appsec-configs dir
	if err = os.MkdirAll(filepath.Join(t.RuntimePath, "appsec-configs"), os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.RuntimePath, err)
	}

	//if it's an appsec rule test, we need acquis and appsec profile
	if len(t.Config.AppsecRules) > 0 {
		// copy template acquis file to runtime folder
		log.Debugf("copying %s to %s", t.TemplateAcquisPath, t.RuntimeAcquisFilePath)

		if err = Copy(t.TemplateAcquisPath, t.RuntimeAcquisFilePath); err != nil {
			return fmt.Errorf("unable to copy '%s' to '%s': %v", t.TemplateAcquisPath, t.RuntimeAcquisFilePath, err)
		}

		log.Debugf("copying %s to %s", t.TemplateAppsecProfilePath, filepath.Join(t.RuntimePath, "appsec-configs", "config.yaml"))
		// copy template appsec-config file to runtime folder
		if err = Copy(t.TemplateAppsecProfilePath, filepath.Join(t.RuntimePath, "appsec-configs", "config.yaml")); err != nil {
			return fmt.Errorf("unable to copy '%s' to '%s': %v", t.TemplateAppsecProfilePath, filepath.Join(t.RuntimePath, "appsec-configs", "config.yaml"), err)
		}
	} else { //otherwise we drop a blank acquis file
		if err = os.WriteFile(t.RuntimeAcquisFilePath, []byte(""), os.ModePerm); err != nil {
			return fmt.Errorf("unable to write blank acquis file '%s': %s", t.RuntimeAcquisFilePath, err)
		}
	}

	// install the hub in the runtime folder
	if err = t.InstallHub(); err != nil {
		return fmt.Errorf("unable to install hub in '%s': %s", t.RuntimeHubPath, err)
	}

	if t.Config.LogFile != "" {
		return t.RunWithLogFile()
	} else if t.Config.NucleiTemplate != "" {
		return t.RunWithNucleiTemplate()
	} else {
		return fmt.Errorf("log file or nuclei template must be set in '%s'", t.Name)
	}
}
