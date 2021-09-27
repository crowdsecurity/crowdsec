package cstest

import (
	"bufio"
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
	Parsers       []string `yaml:"parsers"`
	Scenarios     []string `yaml:"scenarios"`
	PostOVerflows []string `yaml:"postoverflows"`
	Collections   []string `yaml:"collections"`
	LogFile       string   `yaml:"log_file"`
	LogType       string   `yaml:"log_type"`
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

	ResultsPath string
	ResultFile  string

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

	AssertFile        string
	AutoGenAssert     bool
	AutoGenAssertData string
	NbAssert          int
}

const (
	parserAssertFileName   = "parser.assert"
	parserResultFileName   = "parser-dump.yaml"
	crowdsecPatternsFolder = "/etc/crowdsec/patterns/"
)

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
		ResultFile:                filepath.Join(resultPath, parserResultFileName),
		RuntimeHubConfig: &csconfig.Hub{
			HubDir:       runtimeHubFolder,
			ConfigDir:    runtimeFolder,
			HubIndexFile: hubTest.HubIndexFile,
		},
		Config:                 configFileData,
		HubPath:                hubTest.HubPath,
		HubTestPath:            hubTest.HubTestPath,
		HubIndexFile:           hubTest.HubIndexFile,
		TemplateConfigPath:     hubTest.TemplateConfigPath,
		TemplateProfilePath:    hubTest.TemplateProfilePath,
		TemplateSimulationPath: hubTest.TemplateSimulationPath,
		HubIndex:               hubTest.HubIndex,
		AssertFile:             filepath.Join(testPath, parserAssertFileName),
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
				return fmt.Errorf("unable to symlink parser '%s' to '%s': %s", hubDirParserPath, parserDirParserPath, err)
			}
		} else {
			// we check if its a custom parser
			customParserPath := filepath.Join(t.HubPath, parser)
			if _, err := os.Stat(customParserPath); os.IsNotExist(err) {
				return fmt.Errorf("parser '%s' doesn't exist in the hub and doesn't appear to be a custom one.", parser)
			}

			customParserPathSplit := strings.Split(customParserPath, "/")
			customParserName := customParserPathSplit[len(customParserPathSplit)-1]
			// because path is parsers/<stage>/<author>/parser.yaml and we wan't the stage
			customParserStage := customParserPathSplit[len(customParserPathSplit)-3]
			// check if stage exist
			hubStagePath := filepath.Join(t.HubPath, fmt.Sprintf("parsers/%s", customParserStage))

			if _, err := os.Stat(hubStagePath); os.IsNotExist(err) {
				return fmt.Errorf("stage '%s' extracted from '%s' doesn't exist in the hub", customParserStage, hubStagePath)
			}

			parserDirDest = fmt.Sprintf("%s/parsers/%s/", t.RuntimePath, customParserStage)
			if err := os.MkdirAll(parserDirDest, os.ModePerm); err != nil {
				return fmt.Errorf("unable to create folder '%s': %s", parserDirDest, err)
			}

			customParserDest := filepath.Join(parserDirDest, customParserName)
			// if path to parser exist, copy it
			if err := Copy(customParserPath, customParserDest); err != nil {
				return fmt.Errorf("unable to copy custom parser '%s' to '%s': %s", customParserPath, customParserDest, err)
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
				return fmt.Errorf("unable to symlink scenario '%s' to '%s': %s", hubDirScenarioPath, scenarioDirParserPath, err)
			}
		} else {
			// we check if its a custom scenario
			customScenarioPath := filepath.Join(t.HubPath, scenario)
			if _, err := os.Stat(customScenarioPath); os.IsNotExist(err) {
				return fmt.Errorf("scenarios '%s' doesn't exist in the hub and doesn't appear to be a custom one.", scenario)
			}

			scenarioDirDest = fmt.Sprintf("%s/scenarios/", t.RuntimePath)

			scenarioFileName := filepath.Base(customScenarioPath)
			scenarioFileDest := filepath.Join(scenarioDirDest, scenarioFileName)
			if err := Copy(customScenarioPath, scenarioFileDest); err != nil {
				return fmt.Errorf("unable to copy scenario from '%s' to '%s': %s", customScenarioPath, scenarioFileDest, err)
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
				return fmt.Errorf("unable to symlink postoverflow '%s' to '%s': %s", hubDirPostoverflowPath, postoverflowDirParserPath, err)
			}
		} else {
			// we check if its a custom postoverflow
			customPostOverflowPath := filepath.Join(t.HubPath, postoverflow)
			if _, err := os.Stat(customPostOverflowPath); os.IsNotExist(err) {
				return fmt.Errorf("postoverflow '%s' doesn't exist in the hub and doesn't appear to be a custom one.", postoverflow)
			}

			customPostOverflowPathSplit := strings.Split(customPostOverflowPath, "/")
			customPostoverflowName := customPostOverflowPathSplit[len(customPostOverflowPathSplit)-1]
			// because path is postoverflows/<stage>/<author>/parser.yaml and we wan't the stage
			customPostoverflowStage := customPostOverflowPathSplit[len(customPostOverflowPathSplit)-3]

			// check if stage exist
			hubStagePath := filepath.Join(t.HubPath, fmt.Sprintf("postoverflows/%s", customPostoverflowStage))

			if _, err := os.Stat(hubStagePath); os.IsNotExist(err) {
				return fmt.Errorf("stage '%s' from extracted '%s' doesn't exist in the hub", customPostoverflowStage, hubStagePath)
			}

			postoverflowDirDest = fmt.Sprintf("%s/postoverflows/%s/", t.RuntimePath, customPostoverflowStage)
			if err := os.MkdirAll(postoverflowDirDest, os.ModePerm); err != nil {
				return fmt.Errorf("unable to create folder '%s': %s", postoverflowDirDest, err)
			}

			customPostoverflowDest := filepath.Join(postoverflowDirDest, customPostoverflowName)
			// if path to postoverflow exist, copy it
			if err := Copy(customPostOverflowPath, customPostoverflowDest); err != nil {
				return fmt.Errorf("unable to copy custom parser '%s' to '%s': %s", customPostOverflowPath, customPostoverflowDest, err)
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
			log.Printf("parser '%s' installed succesfully in runtime environment", parserName)
		}
	}

	// install data for scenarios if needed
	ret = cwhub.GetItemMap(cwhub.SCENARIOS)
	for scenarioName, item := range ret {
		if item.Installed {
			if err := cwhub.DownloadDataIfNeeded(t.RuntimeHubConfig, item, true); err != nil {
				return fmt.Errorf("unable to download data for parser '%s': %+v", scenarioName, err)
			}
			log.Printf("scenario '%s' installed succesfully in runtime environment", scenarioName)
		}
	}

	// install data for postoverflows if needed
	ret = cwhub.GetItemMap(cwhub.PARSERS_OVFLW)
	for postoverflowName, item := range ret {
		if item.Installed {
			if err := cwhub.DownloadDataIfNeeded(t.RuntimeHubConfig, item, true); err != nil {
				return fmt.Errorf("unable to download data for parser '%s': %+v", postoverflowName, err)
			}
			log.Printf("postoverflow '%s' installed succesfully in runtime environment", postoverflowName)
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
		return fmt.Errorf("unable to stat log file '%s'", logFileStat)
	}
	if logFileStat.Size() == 0 {
		return fmt.Errorf("Log file '%s' is empty, please fill it with log", logFile)
	}

	cmdArgs := []string{"-c", t.RuntimeConfigFilePath, "machines", "add", "testMachine", "--auto"}
	cscliRegisterCmd := exec.Command(t.CscliPath, cmdArgs...)
	log.Debugf("%s", cscliRegisterCmd.String())
	output, err := cscliRegisterCmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(output))
		return fmt.Errorf("fail to run '%s' for test '%s': %v", cscliRegisterCmd.String(), t.Name, err)
	}

	cmdArgs = []string{"-c", t.RuntimeConfigFilePath, "-type", logType, "-dsn", dsn, "-dump-data", t.ResultsPath}
	crowdsecCmd := exec.Command(t.CrowdSecPath, cmdArgs...)
	log.Debugf("%s", crowdsecCmd.String())
	output, err = crowdsecCmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(output))
		return fmt.Errorf("fail to run '%s' for test '%s': %v", crowdsecCmd.String(), t.Name, err)
	}

	if err := os.Chdir(currentDir); err != nil {
		return fmt.Errorf("can't 'cd' to '%s': %s", currentDir, err)
	}

	assertFileStat, err := os.Stat(t.AssertFile)
	if os.IsNotExist(err) {
		return fmt.Errorf("assertion file '%s' for test '%s' doesn't exist in '%s', exiting", parserAssertFileName, t.Name, testPath)
	}

	if assertFileStat.Size() == 0 {
		assertData, err := autogenParserAssertsFromFile(t.ResultFile)
		if err != nil {
			return fmt.Errorf("couldn't generate assertion: %s", err.Error())
		}
		t.AutoGenAssertData = assertData
		t.AutoGenAssert = true
	} else {
		file, err := os.Open(t.AssertFile)

		if err != nil {
			return fmt.Errorf("failed to open")
		}

		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)

		pdump, err := LoadParserDump(t.ResultFile)
		if err != nil {
			return fmt.Errorf("loading parser dump file: %+v", err)
		}

		t.NbAssert = 0
		for scanner.Scan() {
			if scanner.Text() == "" {
				continue
			}
			ok, err := runOneParserAssert(scanner.Text(), pdump)
			if err != nil {
				return fmt.Errorf("unable to run assert '%s': %+v", scanner.Text(), err)
			}
			t.NbAssert += 1
			if !ok {
				log.Debugf("%s is FALSE", scanner.Text())
				//fmt.SPrintf(" %s '%s'\n", emoji.RedSquare, scanner.Text())
				t.Success = false
				t.ErrorsList = append(t.ErrorsList, scanner.Text())
				continue
			}
			//fmt.Printf(" %s '%s'\n", emoji.GreenSquare, scanner.Text())

		}
		file.Close()
		if t.NbAssert == 0 {
			assertData, err := autogenParserAssertsFromFile(t.ResultFile)
			if err != nil {
				return fmt.Errorf("couldn't generate assertion: %s", err.Error())
			}
			t.AutoGenAssertData = assertData
			t.AutoGenAssert = true
		}
	}
	if len(t.ErrorsList) == 0 {
		t.Success = true
	}
	return nil
}
