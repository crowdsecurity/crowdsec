package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AlecAivazis/survey/v2"
	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/enescakir/emoji"
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
	cmdHubTest.PersistentFlags().StringVar(&crowdsecPath, "crowdsec", "/usr/local/bin/crowdsec", "Path to crowdsec")
	cmdHubTest.PersistentFlags().StringVar(&cscliPath, "cscli", "/usr/local/bin cscli", "Path to cscli")

	var cmdHubTestParser = &cobra.Command{
		Use:               "parser",
		Short:             "parser",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
	}

	var cmdHubTestParserAdd = &cobra.Command{
		Use:   "add",
		Short: "add [test_name]",
		Example: `cscli hubtest parser add my-awesome-parser --type syslog
cscli hubtest parser add my-nginx-custom-parer --type nginx`,
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
			log.Infof("Created '%s'", testPath)

			logFileName := fmt.Sprintf("%s.log", testName)
			logFilePath := filepath.Join(testPath, logFileName)
			logFile, err := os.Create(logFilePath)
			if err != nil {
				log.Fatal(err)
			}
			logFile.Close()

			parserAssertFilePath := filepath.Join(testPath, "parser.assert")
			parserAssertFile, err := os.Create(parserAssertFilePath)
			if err != nil {
				log.Fatal(err)
			}
			parserAssertFile.Close()

			configFileData := &cstest.HubTestItemConfig{
				Parsers:       []string{"crowdsecurity/syslog-logs"},
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
				if test.AutoGenAssert {
					log.Warningf("Assert file '%s' is empty, generating assertion:", test.AssertFile)
					fmt.Println()
					fmt.Printf(test.AutoGenAssertData)
					if err := test.Clean(); err != nil {
						log.Fatalf("unable to clean test '%s' env: %s", test.Name, err)
					}
				} else if test.Success {
					fmt.Printf("Test '%s' passed successfully %s\n", test.Name, emoji.GreenSquare)
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

	cmdHubTestParser.AddCommand(cmdHubTestParserRun)

	var cmdHubTestParserClean = &cobra.Command{
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
	cmdHubTestParser.AddCommand(cmdHubTestParserClean)

	var evalExpression string
	var cmdHubTestParserEval = &cobra.Command{
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
				resultDump, err := cstest.LoadParserDump(test.ResultFile)
				if err != nil {
					log.Fatalf("can't load test results from '%s': %+v", test.ResultFile, err)
				}
				output, err := cstest.EvalExpression(evalExpression, resultDump)
				if err != nil {
					log.Fatalf(err.Error())
				}
				fmt.Printf(output)
			}
		},
	}
	cmdHubTestParserEval.PersistentFlags().StringVarP(&evalExpression, "expr", "e", "", "Expression to eval")
	cmdHubTestParser.AddCommand(cmdHubTestParserEval)

	cmdHubTest.AddCommand(cmdHubTestParser)
	return cmdHubTest
}
