package cstest

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type HubTestItemConfig struct {
	Parsers       []string          `yaml:"parsers"`
	Scenarios     []string          `yaml:"scenarios"`
	PostOVerflows []string          `yaml:"postoverflows"`
	LogFile       string            `yaml:"log_file"`
	LogType       string            `yaml:"log_type"`
	Labels        map[string]string `yaml:"labels"`
	IgnoreParsers bool              `yaml:"ignore_parsers"` // if we test a scenario, we don't want to assert on Parser
}

type HubIndex struct {
	Data map[string]map[string]cwhub.Item
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
	RuntimeHubConfig          *csconfig.Hub

	ResultsPath          string
	ParserResultFile     string
	ScenarioResultFile   string
	BucketPourResultFile string

	HubPath                string
	HubTestPath            string
	HubIndexFile           string
	TemplateConfigPath     string
	TemplateProfilePath    string
	TemplateSimulationPath string
	HubIndex               *HubIndex

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

var crowdsecPatternsFolder = csconfig.DefaultConfigPath("patterns")

func NewTest(name string, hubTest *HubTest) (*HubTestItem, error) {
	testPath := filepath.Join(hubTest.HubTestPath, name)
	runtimeFolder := filepath.Join(testPath, "runtime")
	runtimeHubFolder := filepath.Join(runtimeFolder, "hub")
	configFilePath := filepath.Join(testPath, "config.yaml")
	resultPath := filepath.Join(testPath, "results")

	// read test configuration file
	configFileData := &HubTestItemConfig{}
	yamlFile, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		log.Printf("no config file found in '%s': %v", testPath, err)
	}
	err = yaml.Unmarshal(yamlFile, configFileData)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal: %v", err)
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
		ResultsPath:               resultPath,
		ParserResultFile:          filepath.Join(resultPath, ParserResultFileName),
		ScenarioResultFile:        filepath.Join(resultPath, ScenarioResultFileName),
		BucketPourResultFile:      filepath.Join(resultPath, BucketPourResultFileName),
		RuntimeHubConfig: &csconfig.Hub{
			HubDir:       runtimeHubFolder,
			ConfigDir:    runtimeFolder,
			HubIndexFile: hubTest.HubIndexFile,
			DataDir:      filepath.Join(runtimeFolder, "data"),
		},
		Config:                 configFileData,
		HubPath:                hubTest.HubPath,
		HubTestPath:            hubTest.HubTestPath,
		HubIndexFile:           hubTest.HubIndexFile,
		TemplateConfigPath:     hubTest.TemplateConfigPath,
		TemplateProfilePath:    hubTest.TemplateProfilePath,
		TemplateSimulationPath: hubTest.TemplateSimulationPath,
		HubIndex:               hubTest.HubIndex,
		ScenarioAssert:         ScenarioAssert,
		ParserAssert:           ParserAssert,
		CustomItemsLocation:    []string{hubTest.HubPath, testPath},
	}, nil
}

func (t *HubTestItem) InstallHub() error {
	// install parsers in runtime environment
	for _, parser := range t.Config.Parsers {
		if parser == "" {
			continue
		}
		var parserDirDest string
		if hubParser, ok := t.HubIndex.Data[cwhub.PARSERS][parser]; ok {
			parserSource, err := filepath.Abs(filepath.Join(t.HubPath, hubParser.RemotePath))
			if err != nil {
				return fmt.Errorf("can't get absolute path of '%s': %s", parserSource, err)
			}
			parserFileName := filepath.Base(parserSource)

			// runtime/hub/parsers/s00-raw/crowdsecurity/
			hubDirParserDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(hubParser.RemotePath))

			// runtime/parsers/s00-raw/
			parserDirDest = fmt.Sprintf("%s/parsers/%s/", t.RuntimePath, hubParser.Stage)

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

				customParserPathSplit := strings.Split(customParserPath, "/")
				customParserName := customParserPathSplit[len(customParserPathSplit)-1]
				// because path is parsers/<stage>/<author>/parser.yaml and we wan't the stage
				customParserStage := customParserPathSplit[len(customParserPathSplit)-3]

				// check if stage exist
				hubStagePath := filepath.Join(t.HubPath, fmt.Sprintf("parsers/%s", customParserStage))

				if _, err := os.Stat(hubStagePath); os.IsNotExist(err) {
					continue
					//return fmt.Errorf("stage '%s' extracted from '%s' doesn't exist in the hub", customParserStage, hubStagePath)
				}

				parserDirDest = fmt.Sprintf("%s/parsers/%s/", t.RuntimePath, customParserStage)
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
		var scenarioDirDest string
		if hubScenario, ok := t.HubIndex.Data[cwhub.SCENARIOS][scenario]; ok {
			scenarioSource, err := filepath.Abs(filepath.Join(t.HubPath, hubScenario.RemotePath))
			if err != nil {
				return fmt.Errorf("can't get absolute path to: %s", scenarioSource)
			}
			scenarioFileName := filepath.Base(scenarioSource)

			// runtime/hub/scenarios/crowdsecurity/
			hubDirScenarioDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(hubScenario.RemotePath))

			// runtime/parsers/scenarios/
			scenarioDirDest = fmt.Sprintf("%s/scenarios/", t.RuntimePath)

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

				scenarioDirDest = fmt.Sprintf("%s/scenarios/", t.RuntimePath)
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

	// install postoverflows in runtime environment
	for _, postoverflow := range t.Config.PostOVerflows {
		if postoverflow == "" {
			continue
		}
		var postoverflowDirDest string
		if hubPostOverflow, ok := t.HubIndex.Data[cwhub.PARSERS_OVFLW][postoverflow]; ok {
			postoverflowSource, err := filepath.Abs(filepath.Join(t.HubPath, hubPostOverflow.RemotePath))
			if err != nil {
				return fmt.Errorf("can't get absolute path of '%s': %s", postoverflowSource, err)
			}
			postoverflowFileName := filepath.Base(postoverflowSource)

			// runtime/hub/postoverflows/s00-enrich/crowdsecurity/
			hubDirPostoverflowDest := filepath.Join(t.RuntimeHubPath, filepath.Dir(hubPostOverflow.RemotePath))

			// runtime/postoverflows/s00-enrich
			postoverflowDirDest = fmt.Sprintf("%s/postoverflows/%s/", t.RuntimePath, hubPostOverflow.Stage)

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

				postoverflowDirDest = fmt.Sprintf("%s/postoverflows/%s/", t.RuntimePath, customPostoverflowStage)
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

	// load installed hub
	err := cwhub.GetHubIdx(t.RuntimeHubConfig)
	if err != nil {
		log.Fatalf("can't local sync the hub: %+v", err)
	}

	// install data for parsers if needed
	ret := cwhub.GetItemMap(cwhub.PARSERS)
	for parserName, item := range ret {
		if item.Installed {
			if err := cwhub.DownloadDataIfNeeded(t.RuntimeHubConfig, item, true); err != nil {
				return fmt.Errorf("unable to download data for parser '%s': %+v", parserName, err)
			}
			log.Debugf("parser '%s' installed succesfully in runtime environment", parserName)
		}
	}

	// install data for scenarios if needed
	ret = cwhub.GetItemMap(cwhub.SCENARIOS)
	for scenarioName, item := range ret {
		if item.Installed {
			if err := cwhub.DownloadDataIfNeeded(t.RuntimeHubConfig, item, true); err != nil {
				return fmt.Errorf("unable to download data for parser '%s': %+v", scenarioName, err)
			}
			log.Debugf("scenario '%s' installed succesfully in runtime environment", scenarioName)
		}
	}

	// install data for postoverflows if needed
	ret = cwhub.GetItemMap(cwhub.PARSERS_OVFLW)
	for postoverflowName, item := range ret {
		if item.Installed {
			if err := cwhub.DownloadDataIfNeeded(t.RuntimeHubConfig, item, true); err != nil {
				return fmt.Errorf("unable to download data for parser '%s': %+v", postoverflowName, err)
			}
			log.Debugf("postoverflow '%s' installed succesfully in runtime environment", postoverflowName)
		}
	}

	return nil
}

func (t *HubTestItem) Clean() error {
	return os.RemoveAll(t.RuntimePath)
}

func (t *HubTestItem) Run() error {
	t.Success = false
	t.ErrorsList = make([]string, 0)

	testPath := filepath.Join(t.HubTestPath, t.Name)
	if _, err := os.Stat(testPath); os.IsNotExist(err) {
		return fmt.Errorf("test '%s' doesn't exist in '%s', exiting", t.Name, t.HubTestPath)
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("can't get current directory: %+v", err)
	}

	// create runtime folder
	if err := os.MkdirAll(t.RuntimePath, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.RuntimePath, err)
	}

	// create runtime data folder
	if err := os.MkdirAll(t.RuntimeDataPath, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.RuntimeDataPath, err)
	}

	// create runtime hub folder
	if err := os.MkdirAll(t.RuntimeHubPath, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.RuntimeHubPath, err)
	}

	if err := Copy(t.HubIndexFile, filepath.Join(t.RuntimeHubPath, ".index.json")); err != nil {
		return fmt.Errorf("unable to copy .index.json file in '%s': %s", filepath.Join(t.RuntimeHubPath, ".index.json"), err)
	}

	// create results folder
	if err := os.MkdirAll(t.ResultsPath, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create folder '%s': %+v", t.ResultsPath, err)
	}

	// copy template config file to runtime folder
	if err := Copy(t.TemplateConfigPath, t.RuntimeConfigFilePath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %v", t.TemplateConfigPath, t.RuntimeConfigFilePath, err)
	}

	// copy template profile file to runtime folder
	if err := Copy(t.TemplateProfilePath, t.RuntimeProfileFilePath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %v", t.TemplateProfilePath, t.RuntimeProfileFilePath, err)
	}

	// copy template simulation file to runtime folder
	if err := Copy(t.TemplateSimulationPath, t.RuntimeSimulationFilePath); err != nil {
		return fmt.Errorf("unable to copy '%s' to '%s': %v", t.TemplateSimulationPath, t.RuntimeSimulationFilePath, err)
	}

	// copy template patterns folder to runtime folder
	if err := CopyDir(crowdsecPatternsFolder, t.RuntimePatternsPath); err != nil {
		return fmt.Errorf("unable to copy 'patterns' from '%s' to '%s': %s", crowdsecPatternsFolder, t.RuntimePatternsPath, err)
	}

	// install the hub in the runtime folder
	if err := t.InstallHub(); err != nil {
		return fmt.Errorf("unable to install hub in '%s': %s", t.RuntimeHubPath, err)
	}

	logFile := t.Config.LogFile
	logType := t.Config.LogType
	dsn := fmt.Sprintf("file://%s", logFile)

	if err := os.Chdir(testPath); err != nil {
		return fmt.Errorf("can't 'cd' to '%s': %s", testPath, err)
	}

	logFileStat, err := os.Stat(logFile)
	if err != nil {
		return fmt.Errorf("unable to stat log file '%s': %s", logFile, err.Error())
	}
	if logFileStat.Size() == 0 {
		return fmt.Errorf("Log file '%s' is empty, please fill it with log", logFile)
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

	cmdArgs = []string{"-c", t.RuntimeConfigFilePath, "-type", logType, "-dsn", dsn, "-dump-data", t.ResultsPath}
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
		assertFileStat, err := os.Stat(t.ParserAssert.File)
		if os.IsNotExist(err) {
			parserAssertFile, err := os.Create(t.ParserAssert.File)
			if err != nil {
				log.Fatal(err)
			}
			parserAssertFile.Close()
		}
		assertFileStat, err = os.Stat(t.ParserAssert.File)
		if err != nil {
			return fmt.Errorf("error while stats '%s': %s", t.ParserAssert.File, err)
		}

		if assertFileStat.Size() == 0 {
			assertData, err := t.ParserAssert.AutoGenFromFile(t.ParserResultFile)
			if err != nil {
				return fmt.Errorf("couldn't generate assertion: %s", err.Error())
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
		nbScenario += 1
	}
	if nbScenario > 0 {
		assertFileStat, err := os.Stat(t.ScenarioAssert.File)
		if os.IsNotExist(err) {
			scenarioAssertFile, err := os.Create(t.ScenarioAssert.File)
			if err != nil {
				log.Fatal(err)
			}
			scenarioAssertFile.Close()
		}
		assertFileStat, err = os.Stat(t.ScenarioAssert.File)
		if err != nil {
			return fmt.Errorf("error while stats '%s': %s", t.ScenarioAssert.File, err)
		}

		if assertFileStat.Size() == 0 {
			assertData, err := t.ScenarioAssert.AutoGenFromFile(t.ScenarioResultFile)
			if err != nil {
				return fmt.Errorf("couldn't generate assertion: %s", err.Error())
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
