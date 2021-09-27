package main

import (
	"fmt"
	"os"
	"path/filepath"

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
	var outputFormat string
	var hubPath string
	var logType string
	var crowdsecPath string
	var cscliPath string

	var cmdHubTest = &cobra.Command{
		Use:   "hubtest",
		Short: "Run fonctionnals tests on hub configurations",
		Long: `
		Run fonctionnals tests on hub configurations (parsers, scenarios, collections...)
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
	cmdHubTest.PersistentFlags().StringVarP(&outputFormat, "output", "o", "human", "Output format (human, json)")
	cmdHubTest.PersistentFlags().StringVar(&hubPath, "hub", ".", "Path to hub folder")
	cmdHubTest.PersistentFlags().StringVar(&crowdsecPath, "crowdsec", "crowdsec", "Path to crowdsec")
	cmdHubTest.PersistentFlags().StringVar(&cscliPath, "cscli", "cscli", "Path to cscli")

	parsers := []string{}
	postoverflows := []string{}
	scenarios := []string{}
	var cmdHubTestCreate = &cobra.Command{
		Use:   "create",
		Short: "create [test_name]",
		Example: `cscli hubtest create my-awesome-test --type syslog
cscli hubtest create my-nginx-custom-test --type nginx
cscli hubtest create my-scenario-test --parser crowdsecurity/nginx --scenario crowdsecurity/http-probing`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			testName := args[0]
			testPath := filepath.Join(HubTest.HubTestPath, testName)
			if _, err := os.Stat(testPath); os.IsExist(err) {
				log.Fatalf("test '%s' already exists in '%s', exiting", testName, testPath)
			}

			if logType == "" {
				log.Fatalf("please provid a type (--type) for the test")
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
			parserAssertFilePath := filepath.Join(testPath, "parser.assert")
			parserAssertFile, err := os.Create(parserAssertFilePath)
			if err != nil {
				log.Fatal(err)
			}
			parserAssertFile.Close()

			// create empty scenario assertion file
			scenarioAssertFilePath := filepath.Join(testPath, "scenario.assert")
			scenarioAssertFile, err := os.Create(scenarioAssertFilePath)
			if err != nil {
				log.Fatal(err)
			}
			scenarioAssertFile.Close()

			parsers = append(parsers, "crowdsecurity/syslog-logs")
			scenarios = append(scenarios, "crowdsecurity/dateparse-enrich")

			if len(postoverflows) == 0 {
				postoverflows = append(postoverflows, "")
			}

			configFileData := &cstest.HubTestItemConfig{
				Parsers:       parsers,
				Scenarios:     scenarios,
				PostOVerflows: postoverflows,
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
			fmt.Println()
			fmt.Printf("  Test name                   :  %s\n", testName)
			fmt.Printf("  Test path                   :  %s\n", testPath)
			fmt.Printf("  Log file                    :  %s (please fill it with logs)\n", logFilePath)
			fmt.Printf("  Parser assertion file       :  %s (please fill it with assertion)\n", parserAssertFilePath)
			fmt.Printf("  Scenario assertion file     :  %s (please fill it with assertion)\n", parserAssertFilePath)
			fmt.Printf("  Configuration File          :  %s (please fill it with parsers, scenarios...)\n", configFilePath)

		},
	}
	cmdHubTestCreate.PersistentFlags().StringVarP(&logType, "type", "t", "", "Log type of the test")
	cmdHubTestCreate.Flags().StringSliceVarP(&parsers, "parsers", "p", parsers, "Parsers to add to test")
	cmdHubTestCreate.Flags().StringSliceVar(&postoverflows, "postoverflows", postoverflows, "Postoverflows to add to test")
	cmdHubTestCreate.Flags().StringSliceVarP(&scenarios, "scenarios", "s", scenarios, "Scenarios to add to test")
	cmdHubTest.AddCommand(cmdHubTestCreate)

	var cmdHubTestRun = &cobra.Command{
		Use:               "run",
		Short:             "run [test_name]",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			for _, testName := range args {
				test, err := HubTest.LoadTestItem(testName)
				if err != nil {
					log.Fatalf("unable to load test '%s': %s", testName, err)
				}

				log.Infof("Running test '%s'", testName)
				err = test.Run()
				if err != nil {
					log.Errorf("running test '%s' failed: %+v", testName, err)
					test.ErrorsList = append(test.ErrorsList, err.Error())
				}
			}
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			success := true
			for _, test := range HubTest.Tests {
				if test.ParserAssert.AutoGenAssert {
					log.Warningf("Assert file '%s' is empty, generating assertion:", test.ParserAssert.AssertFile)
					fmt.Println()
					fmt.Printf(test.ParserAssert.AutoGenAssertData)
					if err := test.Clean(); err != nil {
						log.Fatalf("unable to clean test '%s' env: %s", test.Name, err)
					}
				} else if test.Success {
					fmt.Printf("Test '%s' passed successfully (%d assertions) %s\n", test.Name, test.ParserAssert.NbAssert, emoji.GreenSquare)
					if err := test.Clean(); err != nil {
						log.Fatalf("unable to clean test '%s' env: %s", test.Name, err)
					}
				} else {
					success = false
					fmt.Printf("Test '%s' failed %s (%d errors)\n", test.Name, emoji.RedSquare, len(test.ErrorsList))
					for _, fail := range test.ErrorsList {
						fmt.Printf("  %s  => %s\n", emoji.RedCircle, fail)
					}

					answer := true
					prompt := &survey.Confirm{
						Message: fmt.Sprintf("Do you want to remove runtime folder for test '%s'? (default: Yes)", test.Name),
						Default: true,
					}
					if err := survey.AskOne(prompt, &answer); err != nil {
						log.Fatalf("unable to ask to remove runtime folder: %s", err)
					}
					if answer {
						if err := test.Clean(); err != nil {
							log.Fatalf("unable to clean test '%s' env: %s", test.Name, err)
						}
					}
				}
			}
			if !success {
				os.Exit(1)
			}
		},
	}

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

	return cmdHubTest
}
