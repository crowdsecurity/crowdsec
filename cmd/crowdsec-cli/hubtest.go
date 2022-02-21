package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/enescakir/emoji"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var (
	HubTest cstest.HubTest
)

func NewHubTestCmd() *cobra.Command {
	/* ---- HUB COMMAND */
	var hubPath string
	var logType string
	var crowdsecPath string
	var cscliPath string

	var cmdHubTest = &cobra.Command{
		Use:   "hubtest",
		Short: "Run functional tests on hub configurations",
		Long: `
		Run functional tests on hub configurations (parsers, scenarios, collections...)
		`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var err error
			HubTest, err = cstest.NewHubTest(hubPath, crowdsecPath, cscliPath)
			if err != nil {
				log.Fatalf("unable to load hubtest: %+v", err)
			}
		},
	}
	cmdHubTest.PersistentFlags().StringVar(&hubPath, "hub", ".", "Path to hub folder")
	cmdHubTest.PersistentFlags().StringVar(&crowdsecPath, "crowdsec", "crowdsec", "Path to crowdsec")
	cmdHubTest.PersistentFlags().StringVar(&cscliPath, "cscli", "cscli", "Path to cscli")

	parsers := []string{}
	postoverflows := []string{}
	scenarios := []string{}
	var ignoreParsers bool
	var labels map[string]string

	var cmdHubTestCreate = &cobra.Command{
		Use:   "create",
		Short: "create [test_name]",
		Example: `cscli hubtest create my-awesome-test --type syslog
cscli hubtest create my-nginx-custom-test --type nginx
cscli hubtest create my-scenario-test --parsers crowdsecurity/nginx --scenarios crowdsecurity/http-probing`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			testName := args[0]
			testPath := filepath.Join(HubTest.HubTestPath, testName)
			if _, err := os.Stat(testPath); os.IsExist(err) {
				log.Fatalf("test '%s' already exists in '%s', exiting", testName, testPath)
			}

			if logType == "" {
				log.Fatalf("please provide a type (--type) for the test")
			}

			if err := os.MkdirAll(testPath, os.ModePerm); err != nil {
				log.Fatalf("unable to create folder '%s': %+v", testPath, err)
			}

			// create empty log file
			logFileName := fmt.Sprintf("%s.log", testName)
			logFilePath := filepath.Join(testPath, logFileName)
			logFile, err := os.Create(logFilePath)
			if err != nil {
				log.Fatal(err)
			}
			logFile.Close()

			// create empty parser assertion file
			parserAssertFilePath := filepath.Join(testPath, cstest.ParserAssertFileName)
			parserAssertFile, err := os.Create(parserAssertFilePath)
			if err != nil {
				log.Fatal(err)
			}
			parserAssertFile.Close()

			// create empty scenario assertion file
			scenarioAssertFilePath := filepath.Join(testPath, cstest.ScenarioAssertFileName)
			scenarioAssertFile, err := os.Create(scenarioAssertFilePath)
			if err != nil {
				log.Fatal(err)
			}
			scenarioAssertFile.Close()

			parsers = append(parsers, "crowdsecurity/syslog-logs")
			parsers = append(parsers, "crowdsecurity/dateparse-enrich")

			if len(scenarios) == 0 {
				scenarios = append(scenarios, "")
			}

			if len(postoverflows) == 0 {
				postoverflows = append(postoverflows, "")
			}

			configFileData := &cstest.HubTestItemConfig{
				Parsers:       parsers,
				Scenarios:     scenarios,
				PostOVerflows: postoverflows,
				LogFile:       logFileName,
				LogType:       logType,
				IgnoreParsers: ignoreParsers,
				Labels:        labels,
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
			fmt.Println()
			fmt.Printf("  Test name                   :  %s\n", testName)
			fmt.Printf("  Test path                   :  %s\n", testPath)
			fmt.Printf("  Log file                    :  %s (please fill it with logs)\n", logFilePath)
			fmt.Printf("  Parser assertion file       :  %s (please fill it with assertion)\n", parserAssertFilePath)
			fmt.Printf("  Scenario assertion file     :  %s (please fill it with assertion)\n", scenarioAssertFilePath)
			fmt.Printf("  Configuration File          :  %s (please fill it with parsers, scenarios...)\n", configFilePath)

		},
	}
	cmdHubTestCreate.PersistentFlags().StringVarP(&logType, "type", "t", "", "Log type of the test")
	cmdHubTestCreate.Flags().StringSliceVarP(&parsers, "parsers", "p", parsers, "Parsers to add to test")
	cmdHubTestCreate.Flags().StringSliceVar(&postoverflows, "postoverflows", postoverflows, "Postoverflows to add to test")
	cmdHubTestCreate.Flags().StringSliceVarP(&scenarios, "scenarios", "s", scenarios, "Scenarios to add to test")
	cmdHubTestCreate.PersistentFlags().BoolVar(&ignoreParsers, "ignore-parsers", false, "Don't run test on parsers")
	cmdHubTest.AddCommand(cmdHubTestCreate)

	var noClean bool
	var runAll bool
	var forceClean bool
	var cmdHubTestRun = &cobra.Command{
		Use:               "run",
		Short:             "run [test_name]",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if !runAll && len(args) == 0 {
				cmd.Help()
				fmt.Println("Please provide test to run or --all flag")
				os.Exit(1)
			}

			if runAll {
				if err := HubTest.LoadAllTests(); err != nil {
					log.Fatalf("unable to load all tests: %+v", err)
				}
			} else {
				for _, testName := range args {
					_, err := HubTest.LoadTestItem(testName)
					if err != nil {
						log.Fatalf("unable to load test '%s': %s", testName, err)
					}
				}
			}

			for _, test := range HubTest.Tests {
				if csConfig.Cscli.Output == "human" {
					log.Infof("Running test '%s'", test.Name)
				}
				err := test.Run()
				if err != nil {
					log.Errorf("running test '%s' failed: %+v", test.Name, err)
				}
			}

		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			success := true
			testResult := make(map[string]bool)
			for _, test := range HubTest.Tests {
				if test.AutoGen {
					if test.ParserAssert.AutoGenAssert {
						log.Warningf("Assert file '%s' is empty, generating assertion:", test.ParserAssert.File)
						fmt.Println()
						fmt.Println(test.ParserAssert.AutoGenAssertData)
					}
					if test.ScenarioAssert.AutoGenAssert {
						log.Warningf("Assert file '%s' is empty, generating assertion:", test.ScenarioAssert.File)
						fmt.Println()
						fmt.Println(test.ScenarioAssert.AutoGenAssertData)
					}
					if !noClean {
						if err := test.Clean(); err != nil {
							log.Fatalf("unable to clean test '%s' env: %s", test.Name, err)
						}
					}
					fmt.Printf("\nPlease fill your assert file(s) for test '%s', exiting\n", test.Name)
					os.Exit(1)
				}
				testResult[test.Name] = test.Success
				if test.Success {
					if csConfig.Cscli.Output == "human" {
						log.Infof("Test '%s' passed successfully (%d assertions)\n", test.Name, test.ParserAssert.NbAssert+test.ScenarioAssert.NbAssert)
					}
					if !noClean {
						if err := test.Clean(); err != nil {
							log.Fatalf("unable to clean test '%s' env: %s", test.Name, err)
						}
					}
				} else {
					success = false
					cleanTestEnv := false
					if csConfig.Cscli.Output == "human" {
						if len(test.ParserAssert.Fails) > 0 {
							fmt.Println()
							log.Errorf("Parser test '%s' failed (%d errors)\n", test.Name, len(test.ParserAssert.Fails))
							for _, fail := range test.ParserAssert.Fails {
								fmt.Printf("(L.%d)  %s  => %s\n", fail.Line, emoji.RedCircle, fail.Expression)
								fmt.Printf("        Actual expression values:\n")
								for key, value := range fail.Debug {
									fmt.Printf("            %s = '%s'\n", key, strings.TrimSuffix(value, "\n"))
								}
								fmt.Println()
							}
						}
						if len(test.ScenarioAssert.Fails) > 0 {
							fmt.Println()
							log.Errorf("Scenario test '%s' failed (%d errors)\n", test.Name, len(test.ScenarioAssert.Fails))
							for _, fail := range test.ScenarioAssert.Fails {
								fmt.Printf("(L.%d)  %s  => %s\n", fail.Line, emoji.RedCircle, fail.Expression)
								fmt.Printf("        Actual expression values:\n")
								for key, value := range fail.Debug {
									fmt.Printf("            %s = '%s'\n", key, strings.TrimSuffix(value, "\n"))
								}
								fmt.Println()
							}
						}
						if !forceClean && !noClean {
							prompt := &survey.Confirm{
								Message: fmt.Sprintf("\nDo you want to remove runtime folder for test '%s'? (default: Yes)", test.Name),
								Default: true,
							}
							if err := survey.AskOne(prompt, &cleanTestEnv); err != nil {
								log.Fatalf("unable to ask to remove runtime folder: %s", err)
							}
						}
					}

					if cleanTestEnv || forceClean {
						if err := test.Clean(); err != nil {
							log.Fatalf("unable to clean test '%s' env: %s", test.Name, err)
						}
					}
				}
			}
			if csConfig.Cscli.Output == "human" {
				table := tablewriter.NewWriter(os.Stdout)
				table.SetCenterSeparator("")
				table.SetColumnSeparator("")

				table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
				table.SetAlignment(tablewriter.ALIGN_LEFT)

				table.SetHeader([]string{"Test", "Result"})
				for testName, success := range testResult {
					status := emoji.CheckMarkButton.String()
					if !success {
						status = emoji.CrossMark.String()
					}
					table.Append([]string{testName, status})
				}
				table.Render()
			} else if csConfig.Cscli.Output == "json" {
				jsonResult := make(map[string][]string, 0)
				jsonResult["success"] = make([]string, 0)
				jsonResult["fail"] = make([]string, 0)
				for testName, success := range testResult {
					if success {
						jsonResult["success"] = append(jsonResult["success"], testName)
					} else {
						jsonResult["fail"] = append(jsonResult["fail"], testName)
					}
				}
				jsonStr, err := json.Marshal(jsonResult)
				if err != nil {
					log.Fatalf("unable to json test result: %s", err.Error())
				}
				fmt.Println(string(jsonStr))
			}

			if !success {
				os.Exit(1)
			}
		},
	}
	cmdHubTestRun.Flags().BoolVar(&noClean, "no-clean", false, "Don't clean runtime environment if test succeed")
	cmdHubTestRun.Flags().BoolVar(&forceClean, "clean", false, "Clean runtime environment if test fail")
	cmdHubTestRun.Flags().BoolVar(&runAll, "all", false, "Run all tests")
	cmdHubTest.AddCommand(cmdHubTestRun)

	var cmdHubTestClean = &cobra.Command{
		Use:               "clean",
		Short:             "clean [test_name]",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			for _, testName := range args {
				test, err := HubTest.LoadTestItem(testName)
				if err != nil {
					log.Fatalf("unable to load test '%s': %s", testName, err)
				}
				if err := test.Clean(); err != nil {
					log.Fatalf("unable to clean test '%s' env: %s", test.Name, err)
				}
			}
		},
	}
	cmdHubTest.AddCommand(cmdHubTestClean)

	var cmdHubTestInfo = &cobra.Command{
		Use:               "info",
		Short:             "info [test_name]",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			for _, testName := range args {
				test, err := HubTest.LoadTestItem(testName)
				if err != nil {
					log.Fatalf("unable to load test '%s': %s", testName, err)
				}
				fmt.Println()
				fmt.Printf("  Test name                   :  %s\n", test.Name)
				fmt.Printf("  Test path                   :  %s\n", test.Path)
				fmt.Printf("  Log file                    :  %s\n", filepath.Join(test.Path, test.Config.LogFile))
				fmt.Printf("  Parser assertion file       :  %s\n", filepath.Join(test.Path, cstest.ParserAssertFileName))
				fmt.Printf("  Scenario assertion file     :  %s\n", filepath.Join(test.Path, cstest.ScenarioAssertFileName))
				fmt.Printf("  Configuration File          :  %s\n", filepath.Join(test.Path, "config.yaml"))
			}
		},
	}
	cmdHubTest.AddCommand(cmdHubTestInfo)

	var cmdHubTestList = &cobra.Command{
		Use:               "list",
		Short:             "list",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := HubTest.LoadAllTests(); err != nil {
				log.Fatalf("unable to load all tests: %+v", err)
			}

			table := tablewriter.NewWriter(os.Stdout)
			table.SetCenterSeparator("")
			table.SetColumnSeparator("")

			table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
			table.SetAlignment(tablewriter.ALIGN_LEFT)
			table.SetHeader([]string{"Name", "Path"})
			for _, test := range HubTest.Tests {
				table.Append([]string{test.Name, test.Path})
			}
			table.Render()

		},
	}
	cmdHubTest.AddCommand(cmdHubTestList)

	var showParserCov bool
	var showScenarioCov bool
	var showOnlyPercent bool
	var cmdHubTestCoverage = &cobra.Command{
		Use:               "coverage",
		Short:             "coverage",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := HubTest.LoadAllTests(); err != nil {
				log.Fatalf("unable to load all tests: %+v", err)
			}
			var err error
			scenarioCoverage := []cstest.ScenarioCoverage{}
			parserCoverage := []cstest.ParserCoverage{}
			scenarioCoveragePercent := 0
			parserCoveragePercent := 0
			showAll := false

			if !showScenarioCov && !showParserCov { // if both are false (flag by default), show both
				showAll = true
			}

			if showParserCov || showAll {
				parserCoverage, err = HubTest.GetParsersCoverage()
				if err != nil {
					log.Fatalf("while getting parser coverage : %s", err)
				}
				parserTested := 0
				for _, test := range parserCoverage {
					if test.TestsCount > 0 {
						parserTested += 1
					}
				}
				parserCoveragePercent = int(math.Round((float64(parserTested) / float64(len(parserCoverage)) * 100)))
			}

			if showScenarioCov || showAll {
				scenarioCoverage, err = HubTest.GetScenariosCoverage()
				if err != nil {
					log.Fatalf("while getting scenario coverage: %s", err)
				}
				scenarioTested := 0
				for _, test := range scenarioCoverage {
					if test.TestsCount > 0 {
						scenarioTested += 1
					}
				}
				scenarioCoveragePercent = int(math.Round((float64(scenarioTested) / float64(len(scenarioCoverage)) * 100)))
			}

			if showOnlyPercent {
				if showAll {
					fmt.Printf("parsers=%d%%\nscenarios=%d%%", parserCoveragePercent, scenarioCoveragePercent)
				} else if showParserCov {
					fmt.Printf("parsers=%d%%", parserCoveragePercent)
				} else if showScenarioCov {
					fmt.Printf("scenarios=%d%%", scenarioCoveragePercent)
				}
				os.Exit(0)
			}

			if csConfig.Cscli.Output == "human" {
				if showParserCov || showAll {
					table := tablewriter.NewWriter(os.Stdout)
					table.SetCenterSeparator("")
					table.SetColumnSeparator("")

					table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
					table.SetAlignment(tablewriter.ALIGN_LEFT)

					table.SetHeader([]string{"Parser", "Status", "Number of tests"})
					parserTested := 0
					for _, test := range parserCoverage {
						status := emoji.RedCircle.String()
						if test.TestsCount > 0 {
							status = emoji.GreenCircle.String()
							parserTested += 1
						}
						table.Append([]string{test.Parser, status, fmt.Sprintf("%d times (accross %d tests)", test.TestsCount, len(test.PresentIn))})
					}
					table.Render()
				}

				if showScenarioCov || showAll {
					table := tablewriter.NewWriter(os.Stdout)
					table.SetCenterSeparator("")
					table.SetColumnSeparator("")

					table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
					table.SetAlignment(tablewriter.ALIGN_LEFT)

					table.SetHeader([]string{"Scenario", "Status", "Number of tests"})
					for _, test := range scenarioCoverage {
						status := emoji.RedCircle.String()
						if test.TestsCount > 0 {
							status = emoji.GreenCircle.String()
						}
						table.Append([]string{test.Scenario, status, fmt.Sprintf("%d times (accross %d tests)", test.TestsCount, len(test.PresentIn))})
					}
					table.Render()
				}
				fmt.Println()
				if showParserCov || showAll {
					fmt.Printf("PARSERS    : %d%% of coverage\n", parserCoveragePercent)
				}
				if showScenarioCov || showAll {
					fmt.Printf("SCENARIOS  : %d%% of coverage\n", scenarioCoveragePercent)
				}
			} else if csConfig.Cscli.Output == "json" {
				dump, err := json.MarshalIndent(parserCoverage, "", " ")
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("%s", dump)
				dump, err = json.MarshalIndent(scenarioCoverage, "", " ")
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("%s", dump)
			} else {
				log.Fatalf("only human/json output modes are supported")
			}

		},
	}
	cmdHubTestCoverage.PersistentFlags().BoolVar(&showOnlyPercent, "percent", false, "Show only percentages of coverage")
	cmdHubTestCoverage.PersistentFlags().BoolVar(&showParserCov, "parsers", false, "Show only parsers coverage")
	cmdHubTestCoverage.PersistentFlags().BoolVar(&showScenarioCov, "scenarios", false, "Show only scenarios coverage")
	cmdHubTest.AddCommand(cmdHubTestCoverage)

	var evalExpression string
	var cmdHubTestEval = &cobra.Command{
		Use:               "eval",
		Short:             "eval [test_name]",
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			for _, testName := range args {
				test, err := HubTest.LoadTestItem(testName)
				if err != nil {
					log.Fatalf("can't load test: %+v", err)
				}
				err = test.ParserAssert.LoadTest(test.ParserResultFile)
				if err != nil {
					log.Fatalf("can't load test results from '%s': %+v", test.ParserResultFile, err)
				}
				output, err := test.ParserAssert.EvalExpression(evalExpression)
				if err != nil {
					log.Fatalf(err.Error())
				}
				fmt.Printf(output)
			}
		},
	}
	cmdHubTestEval.PersistentFlags().StringVarP(&evalExpression, "expr", "e", "", "Expression to eval")
	cmdHubTest.AddCommand(cmdHubTestEval)

	var cmdHubTestExplain = &cobra.Command{
		Use:               "explain",
		Short:             "explain [test_name]",
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			for _, testName := range args {
				test, err := HubTest.LoadTestItem(testName)
				if err != nil {
					log.Fatalf("can't load test: %+v", err)
				}
				err = test.ParserAssert.LoadTest(test.ParserResultFile)
				if err != nil {
					err := test.Run()
					if err != nil {
						log.Fatalf("running test '%s' failed: %+v", test.Name, err)
					}
					err = test.ParserAssert.LoadTest(test.ParserResultFile)
					if err != nil {
						log.Fatalf("unable to load parser result after run: %s", err)
					}
				}

				err = test.ScenarioAssert.LoadTest(test.ScenarioResultFile, test.BucketPourResultFile)
				if err != nil {
					err := test.Run()
					if err != nil {
						log.Fatalf("running test '%s' failed: %+v", test.Name, err)
					}
					err = test.ScenarioAssert.LoadTest(test.ScenarioResultFile, test.BucketPourResultFile)
					if err != nil {
						log.Fatalf("unable to load scenario result after run: %s", err)
					}
				}
				opts := cstest.DumpOpts{}
				cstest.DumpTree(*test.ParserAssert.TestData, *test.ScenarioAssert.PourData, opts)
			}
		},
	}
	cmdHubTest.AddCommand(cmdHubTestExplain)

	return cmdHubTest
}
