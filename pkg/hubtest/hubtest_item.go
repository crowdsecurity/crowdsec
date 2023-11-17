package hubtest

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
)

type HubTestItemConfig struct {
	Parsers               []string            `yaml:"parsers"`
	Scenarios             []string            `yaml:"scenarios"`
	PostOverflows         []string            `yaml:"postoverflows"`
	WaapRules             []string            `yaml:"waap-rules"`
	NucleiTemplate        string              `yaml:"nuclei_template"`
	ExpectedNucleiFailure bool                `yaml:"expect_failure"`
	LogFile               string              `yaml:"log_file"`
	LogType               string              `yaml:"log_type"`
	Labels                map[string]string   `yaml:"labels"`
	IgnoreParsers         bool                `yaml:"ignore_parsers"`   // if we test a scenario, we don't want to assert on Parser
	OverrideStatics       []parser.ExtraField `yaml:"override_statics"` //Allow to override statics. Executed before s00
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

	HubPath                 string
	HubTestPath             string
	HubIndexFile            string
	TemplateConfigPath      string
	TemplateProfilePath     string
	TemplateSimulationPath  string
	TemplateAcquisPath      string
	TemplateWaapProfilePath string
	HubIndex                *cwhub.Hub

	Config *HubTestItemConfig

	Success    bool
	ErrorsList []string

	AutoGen        bool
	ParserAssert   *ParserAssert
	ScenarioAssert *ScenarioAssert

	CustomItemsLocation []string
}

const (
	ParserAssertFileName = "parser.assert"
	ParserResultFileName = "parser-dump.yaml"

	ScenarioAssertFileName = "scenario.assert"
	ScenarioResultFileName = "bucket-dump.yaml"

	BucketPourResultFileName = "bucketpour-dump.yaml"
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
		Config:                  configFileData,
		HubPath:                 hubTest.HubPath,
		HubTestPath:             hubTest.HubTestPath,
		HubIndexFile:            hubTest.HubIndexFile,
		TemplateConfigPath:      hubTest.TemplateConfigPath,
		TemplateProfilePath:     hubTest.TemplateProfilePath,
		TemplateSimulationPath:  hubTest.TemplateSimulationPath,
		TemplateAcquisPath:      hubTest.TemplateAcquisPath,
		TemplateWaapProfilePath: hubTest.TemplateWaapProfilePath,
		HubIndex:                hubTest.HubIndex,
		ScenarioAssert:          ScenarioAssert,
		ParserAssert:            ParserAssert,
		CustomItemsLocation:     []string{hubTest.HubPath, testPath},
	}, nil
}

func (t *HubTestItem) InstallHub() error {
	// install parsers in runtime environment
	for _, parser := range t.Config.Parsers {
		if parser == "" {
			continue
		}

		if hubParser, ok := t.HubIndex.Items[cwhub.PARSERS][parser]; ok {
			parserSource, err := filepath.Abs(filepath.Join(t.HubPath, hubParser.RemotePath))
			if err != nil {
				return fmt.Errorf("can't get absolute path of '%s': %s", parserSource, err)
			}

			parserFileName := filepath.Base(parserSource)

			// runtime/hub/parsers/s00-raw/crowdsecurity/
			hubDirParserDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(hubParser.RemotePath))

			// runtime/parsers/s00-raw/
			parserDirDest := fmt.Sprintf("%s/parsers/%s/", t.RuntimePath, hubParser.Stage)

			if err := os.MkdirAll(hubDirParserDest, os.ModePerm); err != nil {
				return fmt.Errorf("unable to create folder '%s': %s", hubDirParserDest, err)
			}

			if err := os.MkdirAll(parserDirDest, os.ModePerm); err != nil {
				return fmt.Errorf("unable to create folder '%s': %s", parserDirDest, err)
			}

			// runtime/hub/parsers/s00-raw/crowdsecurity/syslog-logs.yaml
			hubDirParserPath := filepath.Join(hubDirParserDest, parserFileName)
			if err := Copy(parserSource, hubDirParserPath); err != nil {
				return fmt.Errorf("unable to copy '%s' to '%s': %s", parserSource, hubDirParserPath, err)
			}

			// runtime/parsers/s00-raw/syslog-logs.yaml
			parserDirParserPath := filepath.Join(parserDirDest, parserFileName)
			if err := os.Symlink(hubDirParserPath, parserDirParserPath); err != nil {
				if !os.IsExist(err) {
					return fmt.Errorf("unable to symlink parser '%s' to '%s': %s", hubDirParserPath, parserDirParserPath, err)
				}
			}
		} else {
			customParserExist := false
			for _, customPath := range t.CustomItemsLocation {
				// we check if its a custom parser
				customParserPath := filepath.Join(customPath, parser)
				if _, err := os.Stat(customParserPath); os.IsNotExist(err) {
					continue
					//return fmt.Errorf("parser '%s' doesn't exist in the hub and doesn't appear to be a custom one.", parser)
				}

				customParserPathSplit, customParserName := filepath.Split(customParserPath)
				// because path is parsers/<stage>/<author>/parser.yaml and we wan't the stage
				splittedPath := strings.Split(customParserPathSplit, string(os.PathSeparator))
				customParserStage := splittedPath[len(splittedPath)-3]

				// check if stage exist
				hubStagePath := filepath.Join(t.HubPath, fmt.Sprintf("parsers/%s", customParserStage))

				if _, err := os.Stat(hubStagePath); os.IsNotExist(err) {
					continue
					//return fmt.Errorf("stage '%s' extracted from '%s' doesn't exist in the hub", customParserStage, hubStagePath)
				}

				parserDirDest := fmt.Sprintf("%s/parsers/%s/", t.RuntimePath, customParserStage)
				if err := os.MkdirAll(parserDirDest, os.ModePerm); err != nil {
					continue
					//return fmt.Errorf("unable to create folder '%s': %s", parserDirDest, err)
				}

				customParserDest := filepath.Join(parserDirDest, customParserName)
				// if path to parser exist, copy it
				if err := Copy(customParserPath, customParserDest); err != nil {
					continue
					//return fmt.Errorf("unable to copy custom parser '%s' to '%s': %s", customParserPath, customParserDest, err)
				}

				customParserExist = true
				break
			}
			if !customParserExist {
				return fmt.Errorf("couldn't find custom parser '%s' in the following location: %+v", parser, t.CustomItemsLocation)
			}
		}
	}

	// install scenarios in runtime environment
	for _, scenario := range t.Config.Scenarios {
		if scenario == "" {
			continue
		}

		if hubScenario, ok := t.HubIndex.Items[cwhub.SCENARIOS][scenario]; ok {
			scenarioSource, err := filepath.Abs(filepath.Join(t.HubPath, hubScenario.RemotePath))
			if err != nil {
				return fmt.Errorf("can't get absolute path to: %s", scenarioSource)
			}

			scenarioFileName := filepath.Base(scenarioSource)

			// runtime/hub/scenarios/crowdsecurity/
			hubDirScenarioDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(hubScenario.RemotePath))

			// runtime/parsers/scenarios/
			scenarioDirDest := fmt.Sprintf("%s/scenarios/", t.RuntimePath)

			if err := os.MkdirAll(hubDirScenarioDest, os.ModePerm); err != nil {
				return fmt.Errorf("unable to create folder '%s': %s", hubDirScenarioDest, err)
			}

			if err := os.MkdirAll(scenarioDirDest, os.ModePerm); err != nil {
				return fmt.Errorf("unable to create folder '%s': %s", scenarioDirDest, err)
			}

			// runtime/hub/scenarios/crowdsecurity/ssh-bf.yaml
			hubDirScenarioPath := filepath.Join(hubDirScenarioDest, scenarioFileName)
			if err := Copy(scenarioSource, hubDirScenarioPath); err != nil {
				return fmt.Errorf("unable to copy '%s' to '%s': %s", scenarioSource, hubDirScenarioPath, err)
			}

			// runtime/scenarios/ssh-bf.yaml
			scenarioDirParserPath := filepath.Join(scenarioDirDest, scenarioFileName)
			if err := os.Symlink(hubDirScenarioPath, scenarioDirParserPath); err != nil {
				if !os.IsExist(err) {
					return fmt.Errorf("unable to symlink scenario '%s' to '%s': %s", hubDirScenarioPath, scenarioDirParserPath, err)
				}
			}
		} else {
			customScenarioExist := false
			for _, customPath := range t.CustomItemsLocation {
				// we check if its a custom scenario
				customScenarioPath := filepath.Join(customPath, scenario)
				if _, err := os.Stat(customScenarioPath); os.IsNotExist(err) {
					continue
					//return fmt.Errorf("scenarios '%s' doesn't exist in the hub and doesn't appear to be a custom one.", scenario)
				}

				scenarioDirDest := fmt.Sprintf("%s/scenarios/", t.RuntimePath)
				if err := os.MkdirAll(scenarioDirDest, os.ModePerm); err != nil {
					return fmt.Errorf("unable to create folder '%s': %s", scenarioDirDest, err)
				}

				scenarioFileName := filepath.Base(customScenarioPath)
				scenarioFileDest := filepath.Join(scenarioDirDest, scenarioFileName)
				if err := Copy(customScenarioPath, scenarioFileDest); err != nil {
					continue
					//return fmt.Errorf("unable to copy scenario from '%s' to '%s': %s", customScenarioPath, scenarioFileDest, err)
				}
				customScenarioExist = true
				break
			}
			if !customScenarioExist {
				return fmt.Errorf("couldn't find custom scenario '%s' in the following location: %+v", scenario, t.CustomItemsLocation)
			}
		}
	}

	// install waaprules in runtime environment
	for _, waaprule := range t.Config.WaapRules {
		log.Infof("adding rule '%s'", waaprule)
		if waaprule == "" {
			continue
		}

		if hubWaapRule, ok := t.HubIndex.Items[cwhub.WAAP_RULES][waaprule]; ok {
			waapRuleSource, err := filepath.Abs(filepath.Join(t.HubPath, hubWaapRule.RemotePath))
			if err != nil {
				return fmt.Errorf("can't get absolute path of '%s': %s", waapRuleSource, err)
			}

			waapRuleFilename := filepath.Base(waapRuleSource)

			// runtime/hub/waap-rules/author/waap-rule
			hubDirWaapRuleDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(hubWaapRule.RemotePath))

			// runtime/waap-rules/
			waapRuleDirDest := fmt.Sprintf("%s/waap-rules/", t.RuntimePath)

			if err := os.MkdirAll(hubDirWaapRuleDest, os.ModePerm); err != nil {
				return fmt.Errorf("unable to create folder '%s': %s", hubDirWaapRuleDest, err)
			}

			if err := os.MkdirAll(waapRuleDirDest, os.ModePerm); err != nil {
				return fmt.Errorf("unable to create folder '%s': %s", waapRuleDirDest, err)
			}

			// runtime/hub/waap-rules/crowdsecurity/rule.yaml
			hubDirWaapRulePath := filepath.Join(waapRuleDirDest, waapRuleFilename)
			if err := Copy(waapRuleSource, hubDirWaapRulePath); err != nil {
				return fmt.Errorf("unable to copy '%s' to '%s': %s", waapRuleSource, hubDirWaapRulePath, err)
			}

			// runtime/waap-rules/rule.yaml
			waapRulePath := filepath.Join(waapRuleDirDest, waapRuleFilename)
			if err := os.Symlink(hubDirWaapRulePath, waapRulePath); err != nil {
				if !os.IsExist(err) {
					return fmt.Errorf("unable to symlink waap-rule '%s' to '%s': %s", hubDirWaapRulePath, waapRulePath, err)
				}
			}
		} else {
			customWaapRuleExist := false
			for _, customPath := range t.CustomItemsLocation {
				// we check if its a custom waap-rule
				customWaapRulePath := filepath.Join(customPath, waaprule)
				if _, err := os.Stat(customWaapRulePath); os.IsNotExist(err) {
					continue
				}
				customWaapRulePathSplit := strings.Split(customWaapRulePath, "/")
				customWappRuleName := customWaapRulePathSplit[len(customWaapRulePathSplit)-1]

				waapRuleDirDest := fmt.Sprintf("%s/waap-rules/", t.RuntimePath)
				if err := os.MkdirAll(waapRuleDirDest, os.ModePerm); err != nil {
					return fmt.Errorf("unable to create folder '%s': %s", waapRuleDirDest, err)
				}

				// runtime/waap-rules/
				customWaapRuleDest := fmt.Sprintf("%s/waap-rules/%s", t.RuntimePath, customWappRuleName)
				// if path to postoverflow exist, copy it
				if err := Copy(customWaapRulePath, customWaapRuleDest); err != nil {
					continue
				}
				customWaapRuleExist = true
				break
			}
			if !customWaapRuleExist {
				return fmt.Errorf("couldn't find custom waap-rule '%s' in the following location: %+v", waaprule, t.CustomItemsLocation)
			}
		}
	}

	// install postoverflows in runtime environment
	for _, postoverflow := range t.Config.PostOverflows {
		if postoverflow == "" {
			continue
		}

		if hubPostOverflow, ok := t.HubIndex.Items[cwhub.POSTOVERFLOWS][postoverflow]; ok {
			postoverflowSource, err := filepath.Abs(filepath.Join(t.HubPath, hubPostOverflow.RemotePath))
			if err != nil {
				return fmt.Errorf("can't get absolute path of '%s': %s", postoverflowSource, err)
			}

			postoverflowFileName := filepath.Base(postoverflowSource)

			// runtime/hub/postoverflows/s00-enrich/crowdsecurity/
			hubDirPostoverflowDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(hubPostOverflow.RemotePath))

			// runtime/postoverflows/s00-enrich
			postoverflowDirDest := fmt.Sprintf("%s/postoverflows/%s/", t.RuntimePath, hubPostOverflow.Stage)

			if err := os.MkdirAll(hubDirPostoverflowDest, os.ModePerm); err != nil {
				return fmt.Errorf("unable to create folder '%s': %s", hubDirPostoverflowDest, err)
			}

			if err := os.MkdirAll(postoverflowDirDest, os.ModePerm); err != nil {
				return fmt.Errorf("unable to create folder '%s': %s", postoverflowDirDest, err)
			}

			// runtime/hub/postoverflows/s00-enrich/crowdsecurity/rdns.yaml
			hubDirPostoverflowPath := filepath.Join(hubDirPostoverflowDest, postoverflowFileName)
			if err := Copy(postoverflowSource, hubDirPostoverflowPath); err != nil {
				return fmt.Errorf("unable to copy '%s' to '%s': %s", postoverflowSource, hubDirPostoverflowPath, err)
			}

			// runtime/postoverflows/s00-enrich/rdns.yaml
			postoverflowDirParserPath := filepath.Join(postoverflowDirDest, postoverflowFileName)
			if err := os.Symlink(hubDirPostoverflowPath, postoverflowDirParserPath); err != nil {
				if !os.IsExist(err) {
					return fmt.Errorf("unable to symlink postoverflow '%s' to '%s': %s", hubDirPostoverflowPath, postoverflowDirParserPath, err)
				}
			}
		} else {
			customPostoverflowExist := false
			for _, customPath := range t.CustomItemsLocation {
				// we check if its a custom postoverflow
				customPostOverflowPath := filepath.Join(customPath, postoverflow)
				if _, err := os.Stat(customPostOverflowPath); os.IsNotExist(err) {
					continue
					//return fmt.Errorf("postoverflow '%s' doesn't exist in the hub and doesn't appear to be a custom one.", postoverflow)
				}

				customPostOverflowPathSplit := strings.Split(customPostOverflowPath, "/")
				customPostoverflowName := customPostOverflowPathSplit[len(customPostOverflowPathSplit)-1]
				// because path is postoverflows/<stage>/<author>/parser.yaml and we wan't the stage
				customPostoverflowStage := customPostOverflowPathSplit[len(customPostOverflowPathSplit)-3]

				// check if stage exist
				hubStagePath := filepath.Join(t.HubPath, fmt.Sprintf("postoverflows/%s", customPostoverflowStage))

				if _, err := os.Stat(hubStagePath); os.IsNotExist(err) {
					continue
					//return fmt.Errorf("stage '%s' from extracted '%s' doesn't exist in the hub", customPostoverflowStage, hubStagePath)
				}

				postoverflowDirDest := fmt.Sprintf("%s/postoverflows/%s/", t.RuntimePath, customPostoverflowStage)
				if err := os.MkdirAll(postoverflowDirDest, os.ModePerm); err != nil {
					continue
					//return fmt.Errorf("unable to create folder '%s': %s", postoverflowDirDest, err)
				}

				customPostoverflowDest := filepath.Join(postoverflowDirDest, customPostoverflowName)
				// if path to postoverflow exist, copy it
				if err := Copy(customPostOverflowPath, customPostoverflowDest); err != nil {
					continue
					//return fmt.Errorf("unable to copy custom parser '%s' to '%s': %s", customPostOverflowPath, customPostoverflowDest, err)
				}
				customPostoverflowExist = true
				break
			}
			if !customPostoverflowExist {
				return fmt.Errorf("couldn't find custom postoverflow '%s' in the following location: %+v", postoverflow, t.CustomItemsLocation)
			}
		}
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
	hub, err := cwhub.NewHub(t.RuntimeHubConfig, nil, false)
	if err != nil {
		log.Fatal(err)
	}

	// install data for parsers if needed
	ret := hub.GetItemMap(cwhub.PARSERS)
	for parserName, item := range ret {
		if item.Installed {
			if err := item.DownloadDataIfNeeded(true); err != nil {
				return fmt.Errorf("unable to download data for parser '%s': %+v", parserName, err)
			}

			log.Debugf("parser '%s' installed successfully in runtime environment", parserName)
		}
	}

	// install data for scenarios if needed
	ret = hub.GetItemMap(cwhub.SCENARIOS)
	for scenarioName, item := range ret {
		if item.Installed {
			if err := item.DownloadDataIfNeeded(true); err != nil {
				return fmt.Errorf("unable to download data for parser '%s': %+v", scenarioName, err)
			}

			log.Debugf("scenario '%s' installed successfully in runtime environment", scenarioName)
		}
	}

	// install data for postoverflows if needed
	ret = hub.GetItemMap(cwhub.POSTOVERFLOWS)
	for postoverflowName, item := range ret {
		if item.Installed {
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

	testPath := filepath.Join(t.HubTestPath, t.Name)
	if _, err := os.Stat(testPath); os.IsNotExist(err) {
		return fmt.Errorf("test '%s' doesn't exist in '%s', exiting", t.Name, t.HubTestPath)
	}

	if err := os.Chdir(testPath); err != nil {
		return fmt.Errorf("can't 'cd' to '%s': %s", testPath, err)
	}

	//machine add
	cmdArgs := []string{"-c", t.RuntimeConfigFilePath, "machines", "add", "testMachine", "--auto"}
	cscliRegisterCmd := exec.Command(t.CscliPath, cmdArgs...)

	output, err := cscliRegisterCmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(string(output), "unable to create machine: user 'testMachine': user already exist") {
			fmt.Println(string(output))
			return fmt.Errorf("fail to run '%s' for test '%s': %v", cscliRegisterCmd.String(), t.Name, err)
		}
	}

	//hardcode bouncer key
	cmdArgs = []string{"-c", t.RuntimeConfigFilePath, "bouncers", "add", "waaptests", "-k", "this_is_a_bad_password"}
	cscliBouncerCmd := exec.Command(t.CscliPath, cmdArgs...)

	output, err = cscliBouncerCmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(string(output), "unable to create bouncer: bouncer waaptests already exists") {
			fmt.Println(string(output))
			return fmt.Errorf("fail to run '%s' for test '%s': %v", cscliRegisterCmd.String(), t.Name, err)
		}
	}

	//start crowdsec service
	cmdArgs = []string{"-c", t.RuntimeConfigFilePath}
	crowdsecDaemon := exec.Command(t.CrowdSecPath, cmdArgs...)

	crowdsecDaemon.Start()

	//wait for the waap port to be available

	start := time.Now()

	for {
		conn, err := net.Dial("tcp", "127.0.0.1:4241")
		if err == nil {
			log.Debugf("waap is up after %s", time.Since(start))
			conn.Close()
			break
		}
		time.Sleep(500 * time.Millisecond)
		if time.Since(start) > 10*time.Second {
			log.Fatalf("took more than 10s for waap to be available, abort")
		}
	}

	nucleiConfig := NucleiConfig{
		Path:      "nuclei",
		OutputDir: testPath,
		CmdLineOptions: []string{"-ev", //allow variables from environment
			"-nc",    //no colors in output
			"-dresp", //dump response
			"-j",     //json output
		},
	}

	err = nucleiConfig.RunNucleiTemplate(t.Name, t.Config.NucleiTemplate, "http://127.0.0.1:80/")

	if t.Config.ExpectedNucleiFailure {
		if err != nil && errors.Is(err, NucleiTemplateFail) {
			log.Infof("WAAP test %s failed as expected", t.Name)
			t.Success = true
		} else {
			log.Errorf("WAAP test %s failed:  %s", t.Name, err)
		}
	} else {
		if err == nil {
			log.Infof("WAAP test %s succeeded", t.Name)
			t.Success = true
		} else {
			log.Errorf("WAAP test %s failed:  %s", t.Name, err)
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

	cmdArgs := []string{"-c", t.RuntimeConfigFilePath, "machines", "add", "testMachine", "--auto"}
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

	// create the waap-configs dir
	if err = os.MkdirAll(filepath.Join(t.RuntimePath, "waap-configs"), os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.RuntimePath, err)
	}

	// copy the waap-config file and acquis *only* if nuclei template is set -> it means we're testing waap
	if t.Config.NucleiTemplate != "" {
		// copy template acquis file to runtime folder
		log.Infof("copying %s to %s", t.TemplateAcquisPath, t.RuntimeAcquisFilePath)
		if err = Copy(t.TemplateAcquisPath, t.RuntimeAcquisFilePath); err != nil {
			return fmt.Errorf("unable to copy '%s' to '%s': %v", t.TemplateAcquisPath, t.RuntimeAcquisFilePath, err)
		}

		log.Infof("copying %s to %s", t.TemplateWaapProfilePath, filepath.Join(t.RuntimePath, "waap-configs", "config.yaml"))
		// copy template waap-config file to runtime folder
		if err = Copy(t.TemplateWaapProfilePath, filepath.Join(t.RuntimePath, "waap-configs", "config.yaml")); err != nil {
			return fmt.Errorf("unable to copy '%s' to '%s': %v", t.TemplateWaapProfilePath, filepath.Join(t.RuntimePath, "waap-configs", "config.yaml"), err)
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
