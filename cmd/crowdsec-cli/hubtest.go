package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/enescakir/emoji"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

type ConfigTestFile struct {
	Parsers       []string `yaml:"parsers"`
	Scenarios     []string `yaml:"scenarios"`
	PostOVerflows []string `yaml:"postoverflows"`
	Collections   []string `yaml:"collections"`
	LogFile       string   `yaml:"log_file"`
	LogType       string   `yaml:"log_type"`
}

const (
	templateConfigFile     = "template_config.yaml"
	templateSimulationFile = "template_simulation.yaml"
	templateProfileFile    = "template_profiles.yaml"
	parserAssertFileName   = "parser.assert"
	parserResultFileName   = "parser-dump.yaml"
	crowdsecPatternsFolder = "/etc/crowdsec/patterns/"
)

var (
	hubIndex map[string]map[string]cwhub.Item
)

func InstallHub(configFileData ConfigTestFile, hubConfig *csconfig.Hub, hubPath string, runtimeFolder string, runtimeHubFolder string) error {
	// install parsers in runtime environment
	for _, parser := range configFileData.Parsers {
		if parser == "" {
			continue
		}
		if hubParser, ok := hubIndex[cwhub.PARSERS][parser]; ok {
			parserSource, err := filepath.Abs(filepath.Join(hubPath, hubParser.RemotePath))
			if err != nil {
				return fmt.Errorf("can't get absolute path of '%s': %s", parserSource, err)
			}
			parserFileName := filepath.Base(parserSource)

			// runtime/hub/parsers/s00-raw/crowdsecurity/
			hubDirParserDest := filepath.Join(runtimeHubFolder, filepath.Dir(hubParser.RemotePath))

			// runtime/parsers/s00-raw/
			parserDirDest := fmt.Sprintf("%s/parsers/%s/", runtimeFolder, hubParser.Stage)

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
			return fmt.Errorf("parser '%s' doesn't exist in .index.json, exiting", parser)
		}
	}

	// install scenarios in runtime environment
	for _, scenario := range configFileData.Scenarios {
		if scenario == "" {
			continue
		}
		if hubScenario, ok := hubIndex[cwhub.SCENARIOS][scenario]; ok {
			scenarioSource, err := filepath.Abs(filepath.Join(hubPath, hubScenario.RemotePath))
			if err != nil {
				return fmt.Errorf("can't get absolute path to: %s", scenarioSource)
			}
			scenarioFileName := filepath.Base(scenarioSource)

			// runtime/hub/scenarios/crowdsecurity/
			hubDirScenarioDest := filepath.Join(runtimeHubFolder, filepath.Dir(hubScenario.RemotePath))

			// runtime/parsers/scenarios/
			scenarioDirDest := fmt.Sprintf("%s/scenarios/", runtimeFolder)

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
			return fmt.Errorf("scenario '%s' doesn't exist in .index.json, exiting", scenario)
		}
	}

	// install postoverflows in runtime environment
	for _, postoverflow := range configFileData.PostOVerflows {
		if postoverflow == "" {
			continue
		}
		if hubPostOverflow, ok := hubIndex[cwhub.PARSERS_OVFLW][postoverflow]; ok {
			postoverflowSource, err := filepath.Abs(filepath.Join(hubPath, hubPostOverflow.RemotePath))
			if err != nil {
				return fmt.Errorf("can't get absolute path of '%s': %s", postoverflowSource, err)
			}
			postoverflowFileName := filepath.Base(postoverflowSource)

			// runtime/hub/postoverflows/s00-enrich/crowdsecurity/
			hubDirPostoverflowDest := filepath.Join(runtimeHubFolder, filepath.Dir(hubPostOverflow.RemotePath))

			// runtime/postoverflows/s00-enrich
			postoverflowDirDest := fmt.Sprintf("%s/postoverflows/%s/", runtimeFolder, hubPostOverflow.Stage)

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
			return fmt.Errorf("scenario '%s' doesn't exist in .index.json, exiting", postoverflow)
		}
	}

	// load installed hub
	err := cwhub.GetHubIdx(hubConfig)
	if err != nil {
		log.Fatalf("can't local sync the hub: %+v", err)
	}

	// install data for parsers if needed
	ret := cwhub.GetItemMap(cwhub.PARSERS)
	for parserName, item := range ret {
		if item.Installed {
			if err := cwhub.DownloadDataIfNeeded(hubConfig, item, true); err != nil {
				return fmt.Errorf("unable to download data for parser '%s': %+v", parserName, err)
			}
		}
	}

	// install data for scenarios if needed
	ret = cwhub.GetItemMap(cwhub.SCENARIOS)
	for scenarioName, item := range ret {
		if item.Installed {
			if err := cwhub.DownloadDataIfNeeded(hubConfig, item, true); err != nil {
				return fmt.Errorf("unable to download data for parser '%s': %+v", scenarioName, err)
			}
		}
	}

	// install data for postoverflows if needed
	ret = cwhub.GetItemMap(cwhub.PARSERS_OVFLW)
	for postoverflowName, item := range ret {
		if item.Installed {
			if err := cwhub.DownloadDataIfNeeded(hubConfig, item, true); err != nil {
				return fmt.Errorf("unable to download data for parser '%s': %+v", postoverflowName, err)
			}
		}
	}

	return nil
}

func NewHubTestCmd() *cobra.Command {
	/* ---- HUB COMMAND */
	var outputFormat string

	var hubPath string
	var HubTestPath string
	var hubIndexFile string

	var runtimeFolder string
	var runtimeDataFolder string
	var runtimeHubFolder string
	var runtimePatternsFolder string

	var currentDir string

	var logType string

	var templateConfigFilePath string
	var templateProfilePath string
	var templateSimulationPath string
	var cmdHubTest = &cobra.Command{
		Use:   "hubtest",
		Short: "Run fonctionnals tests on hub configurations",
		Long: `
		Run fonctionnals tests on hub configurations (parsers, scenarios, collections...)
		`,
		Example: `
cscli hubtest add myTest
cscli hubtest inspect myTest 
cscli hubtest run myTest
		`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error

			hubPath, err = filepath.Abs(hubPath)
			if err != nil {
				log.Fatalf("can't get absolute path of hub: %+v", err)
			}

			// we can't use this command without the hub
			if _, err := os.Stat(hubPath); os.IsNotExist(err) {
				log.Fatalf("path to hub doesn't exist, can't run: %+v", err)
			}
			HubTestPath = filepath.Join(hubPath, "./.tests/")

			hubIndexFile = filepath.Join(hubPath, ".index.json")
			bidx, err := ioutil.ReadFile(hubIndexFile)
			if err != nil {
				log.Fatalf("unable to read index file: %s", err)
			}

			// load hub index
			hubIndex, err = cwhub.LoadPkgIndex(bidx)
			if err != nil {
				log.Fatalf("unable to load hub index file: %s", err)
			}

			templateConfigFilePath = filepath.Join(HubTestPath, templateConfigFile)
			templateProfilePath = filepath.Join(HubTestPath, templateProfileFile)
			templateSimulationPath = filepath.Join(HubTestPath, templateSimulationFile)
		},
	}
	cmdHubTest.PersistentFlags().StringVarP(&outputFormat, "output", "o", "human", "Output format (human, json)")
	cmdHubTest.PersistentFlags().StringVar(&hubPath, "hub", ".", "Path to hub folder")

	var cmdHubTestParser = &cobra.Command{
		Use:               "parser",
		Short:             "parser",
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
		},
	}

	var cmdHubTestParserAdd = &cobra.Command{
		Use:               "add",
		Short:             "add [test_name]",
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			testName := args[0]
			testPath := filepath.Join(HubTestPath, testName)
			if _, err := os.Stat(testPath); os.IsExist(err) {
				log.Fatalf("test '%s' already exist in '%s', exiting", testName, testPath)
			}

			if logType == "" {
				log.Fatalf("please provid a type (--type) for the test")
			}

			if err := os.MkdirAll(testPath, os.ModePerm); err != nil {
				log.Fatalf("unable to create folder '%s': %+v", testPath, err)
			}
			log.Infof("Created '%s'", testPath)

			logFileName := fmt.Sprintf("%s.log", testName)
			logFilePath := filepath.Join(testPath, logFileName)
			logFile, err := os.Create(logFilePath)
			if err != nil {
				log.Fatal(err)
			}
			logFile.Close()
			log.Infof("Created empty log file in '%s'", logFilePath)

			parserAssertFilePath := filepath.Join(testPath, "parser.assert")
			parserAssertFile, err := os.Create(parserAssertFilePath)
			if err != nil {
				log.Fatal(err)
			}
			parserAssertFile.Close()
			log.Infof("Created empty log file in '%s'", parserAssertFilePath)

			configFileData := &ConfigTestFile{
				Parsers:       []string{"crowdsecurity/syslog-logs", "crowdsecurity/dateparse-enrich"},
				Scenarios:     []string{""},
				Collections:   []string{""},
				PostOVerflows: []string{""},
				LogFile:       logFileName,
				LogType:       logType,
			}
			configFilePath := filepath.Join(testPath, "config.yaml")
			fd, err := os.OpenFile(configFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
			if err != nil {
				log.Fatalf("open: %s", err)
			}
			data, err := yaml.Marshal(configFileData)
			if err != nil {
				log.Fatalf("marshal: %s", err)
			}
			_, err = fd.Write(data)
			if err != nil {
				log.Fatalf("write: %s", err)
			}
			if err := fd.Close(); err != nil {
				log.Fatalf(" close: %s", err)
			}
			fmt.Printf("  Created log file '%s', please fill with with logs", logFilePath)
			fmt.Printf("  Created log file '%s', please fill with with assertion", parserAssertFilePath)

		},
	}
	cmdHubTestParserAdd.PersistentFlags().StringVarP(&logType, "type", "t", "", "Log type of the test")
	cmdHubTestParser.AddCommand(cmdHubTestParserAdd)

	var cmdHubTestParserRun = &cobra.Command{
		Use:               "run",
		Short:             "run [test_name]",
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			testName := args[0]
			testPath := filepath.Join(HubTestPath, testName)
			if _, err := os.Stat(testPath); os.IsNotExist(err) {
				log.Fatalf("test '%s' doesn't exist in '%s', exiting", testName, HubTestPath)
			}

			configFilePath := filepath.Join(testPath, "config.yaml")
			runtimeFolder = filepath.Join(testPath, "runtime")
			runtimeDataFolder = filepath.Join(runtimeFolder, "data")
			runtimeHubFolder = filepath.Join(runtimeFolder, "hub")
			runtimePatternsFolder = filepath.Join(runtimeFolder, "patterns")

			runtimeConfigFilePath := filepath.Join(runtimeFolder, "config.yaml")
			runtimeProfileFilePath := filepath.Join(runtimeFolder, "profiles.yaml")
			runtimeSimulationFilePath := filepath.Join(runtimeFolder, "simulation.yaml")

			hubConfig := &csconfig.Hub{
				HubDir:       runtimeHubFolder,
				ConfigDir:    runtimeFolder,
				HubIndexFile: hubIndexFile,
			}

			resultsFolder := filepath.Join(testPath, "results")

			currentDir, err = os.Getwd()
			if err != nil {
				log.Fatalf("can't get current directory: %+v", err)
			}

			// read test configuration file
			configFileData := &ConfigTestFile{}
			yamlFile, err := ioutil.ReadFile(configFilePath)
			if err != nil {
				log.Printf("not config file found in '%s': %v", testPath, err)
			}
			err = yaml.Unmarshal(yamlFile, configFileData)
			if err != nil {
				log.Fatalf("Unmarshal: %v", err)
			}

			// create runtime folder
			if err := os.MkdirAll(runtimeFolder, os.ModePerm); err != nil {
				log.Fatalf("unable to create folder '%s': %+v", runtimeFolder, err)
			}

			// create runtime data folder
			if err := os.MkdirAll(runtimeDataFolder, os.ModePerm); err != nil {
				log.Fatalf("unable to create folder '%s': %+v", runtimeDataFolder, err)
			}

			// create runtime hub folder
			if err := os.MkdirAll(runtimeHubFolder, os.ModePerm); err != nil {
				log.Fatalf("unable to create folder '%s': %+v", runtimeHubFolder, err)
			}

			if err := Copy(hubIndexFile, filepath.Join(runtimeHubFolder, ".index.json")); err != nil {
				log.Fatalf("unable to copy .index.json file in '%s': %s", filepath.Join(runtimeHubFolder, ".index.json"), err)
			}

			// create results folder
			if err := os.MkdirAll(resultsFolder, os.ModePerm); err != nil {
				log.Fatalf("unable to create folder '%s': %+v", resultsFolder, err)
			}

			// copy template config file to runtime folder
			if err := Copy(templateConfigFilePath, runtimeConfigFilePath); err != nil {
				log.Fatalf("unable to copy '%s' to '%s': %v", templateConfigFilePath, runtimeConfigFilePath, err)
			}

			// copy template profile file to runtime folder
			if err := Copy(templateProfilePath, runtimeProfileFilePath); err != nil {
				log.Fatalf("unable to copy '%s' to '%s': %v", templateProfilePath, runtimeProfileFilePath, err)
			}

			// copy template simulation file to runtime folder
			if err := Copy(templateSimulationPath, runtimeSimulationFilePath); err != nil {
				log.Fatalf("unable to copy '%s' to '%s': %v", templateSimulationPath, runtimeSimulationFilePath, err)
			}

			// copy template patterns folder to runtime folder
			if err := CopyDir(crowdsecPatternsFolder, runtimePatternsFolder); err != nil {
				log.Fatalf("unable to copy 'patterns' from '%s' to '%s': %s", crowdsecPatternsFolder, runtimePatternsFolder, err)
			}

			// install the hub in the runtime folder
			if err := InstallHub(*configFileData, hubConfig, hubPath, runtimeFolder, runtimeHubFolder); err != nil {
				log.Fatalf("unable to install hub in '%s': %s", runtimeHubFolder, err)
			}

			logFile := configFileData.LogFile
			logType := configFileData.LogType
			dsn := fmt.Sprintf("file://%s", logFile)

			if err := os.Chdir(testPath); err != nil {
				log.Fatalf("can't 'cd' to '%s': %s", testPath, err)
			}

			logFileStat, err := os.Stat(logFile)
			if err != nil {
				log.Fatalf("unable to stat log file '%s'", logFileStat)
			}
			if logFileStat.Size() == 0 {
				log.Fatalf("Log file '%s' is empty, please fill it with log", logFile)
			}

			cmdArgs := []string{"-c", runtimeConfigFilePath, "machines", "add", "testMachine", "--auto"}
			cscliRegisterCmd := exec.Command("cscli", cmdArgs...)
			output, err := cscliRegisterCmd.CombinedOutput()
			if err != nil {
				fmt.Println(string(output))
				log.Fatalf("fail to run '%s' for test '%s': %v", cscliRegisterCmd.String(), testName, err)
			}

			cmdArgs = []string{"-c", runtimeConfigFilePath, "-type", logType, "-dsn", dsn, "-dump-data", resultsFolder}
			crowdsecCmd := exec.Command("crowdsec", cmdArgs...)
			output, err = crowdsecCmd.CombinedOutput()
			if err != nil {
				fmt.Println(string(output))
				log.Fatalf("fail to run '%s' for test '%s': %v", crowdsecCmd.String(), testName, err)
			}

			if err := os.Chdir(currentDir); err != nil {
				log.Fatalf("can't 'cd' to '%s': %s", currentDir, err)
			}

			parserResultFile := filepath.Join(resultsFolder, parserResultFileName)
			assertFile := filepath.Join(testPath, parserAssertFileName)
			assertFileStat, err := os.Stat(assertFile)
			if os.IsNotExist(err) {
				log.Fatalf("assertion file '%s' for test '%s' doesn't exist in '%s', exiting", parserAssertFileName, testName, testPath)
			}

			var errorList []string
			if assertFileStat.Size() == 0 {
				log.Warningf("Empty assert file '%s', generating assertion:", assertFile)
				fmt.Println()
				autogenParserAssertsFromFile(parserResultFile)
			} else {
				errorList = make([]string, 0)
				file, err := os.Open(assertFile)

				if err != nil {
					log.Fatalf("failed to open")
				}

				scanner := bufio.NewScanner(file)
				scanner.Split(bufio.ScanLines)

				pdump, err := loadParserDump(parserResultFile)
				if err != nil {
					log.Fatalf("loading parser dump file: %+v", err)
				}

				for scanner.Scan() {
					if scanner.Text() == "" {
						continue
					}
					ok, err, _ := runOneParserAssert(scanner.Text(), pdump)
					if err != nil {
						log.Fatalf("unable to run assert '%s': %+v", err)
					}
					if !ok {
						//fmt.SPrintf(" %s '%s'\n", emoji.RedSquare, scanner.Text())
						errorList = append(errorList, fmt.Sprintf(" %s '%s'\n", emoji.RedSquare, scanner.Text()))
						continue
					}
					//fmt.Printf(" %s '%s'\n", emoji.GreenSquare, scanner.Text())

				}
				file.Close()
			}
			if len(errorList) > 0 {
				for _, err := range errorList {
					fmt.Printf(err)
				}
			} else {
				fmt.Printf("Test '%s' passed successfully %s", testName, emoji.GreenSquare)
			}
			// if everything went good, we can remove the runtime folder
			if err := os.RemoveAll(runtimeFolder); err != nil {
				log.Fatalf("unable to remove folder '%s':%v", runtimeFolder, err)
			}
		},
	}
	cmdHubTestParser.AddCommand(cmdHubTestParserRun)

	cmdHubTest.AddCommand(cmdHubTestParser)
	return cmdHubTest
}
