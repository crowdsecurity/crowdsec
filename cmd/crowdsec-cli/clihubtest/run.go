package clihubtest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/emoji"
	"github.com/crowdsecurity/crowdsec/pkg/hubtest"
)

func (cli *cliHubTest) run(runAll bool, nucleiTargetHost string, appSecHost string, args []string) error {
	cfg := cli.cfg()

	if !runAll && len(args) == 0 {
		return errors.New("please provide test to run or --all flag")
	}

	hubPtr.NucleiTargetHost = nucleiTargetHost
	hubPtr.AppSecHost = appSecHost

	if runAll {
		if err := hubPtr.LoadAllTests(); err != nil {
			return fmt.Errorf("unable to load all tests: %+v", err)
		}
	} else {
		for _, testName := range args {
			_, err := hubPtr.LoadTestItem(testName)
			if err != nil {
				return fmt.Errorf("unable to load test '%s': %w", testName, err)
			}
		}
	}

	// set timezone to avoid DST issues
	os.Setenv("TZ", "UTC")

	patternDir := cfg.ConfigPaths.PatternDir

	for _, test := range hubPtr.Tests {
		if cfg.Cscli.Output == "human" {
			log.Infof("Running test '%s'", test.Name)
		}

		err := test.Run(patternDir)
		if err != nil {
			log.Errorf("running test '%s' failed: %+v", test.Name, err)
		}
	}

	return nil
}

func printParserFailures(test *hubtest.HubTestItem) {
	if len(test.ParserAssert.Fails) == 0 {
		return
	}

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

func printScenarioFailures(test *hubtest.HubTestItem) {
	if len(test.ScenarioAssert.Fails) == 0 {
		return
	}

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

func (cli *cliHubTest) newRunCmd() *cobra.Command {
	var (
		noClean          bool
		runAll           bool
		forceClean       bool
		nucleiTargetHost string
		appSecHost       string
	)

	cmd := &cobra.Command{
		Use:               "run",
		Short:             "run [test_name]",
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			return cli.run(runAll, nucleiTargetHost, appSecHost, args)
		},
		PersistentPostRunE: func(_ *cobra.Command, _ []string) error {
			cfg := cli.cfg()

			success := true
			testResult := make(map[string]bool)
			for _, test := range hubPtr.Tests {
				if test.AutoGen && !isAppsecTest {
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
							return fmt.Errorf("unable to clean test '%s' env: %w", test.Name, err)
						}
					}

					return fmt.Errorf("please fill your assert file(s) for test '%s', exiting", test.Name)
				}
				testResult[test.Name] = test.Success
				if test.Success {
					if cfg.Cscli.Output == "human" {
						log.Infof("Test '%s' passed successfully (%d assertions)\n", test.Name, test.ParserAssert.NbAssert+test.ScenarioAssert.NbAssert)
					}
					if !noClean {
						if err := test.Clean(); err != nil {
							return fmt.Errorf("unable to clean test '%s' env: %w", test.Name, err)
						}
					}
				} else {
					success = false
					cleanTestEnv := false
					if cfg.Cscli.Output == "human" {
						printParserFailures(test)
						printScenarioFailures(test)
						if !forceClean && !noClean {
							prompt := &survey.Confirm{
								Message: fmt.Sprintf("\nDo you want to remove runtime folder for test '%s'? (default: Yes)", test.Name),
								Default: true,
							}
							if err := survey.AskOne(prompt, &cleanTestEnv); err != nil {
								return fmt.Errorf("unable to ask to remove runtime folder: %w", err)
							}
						}
					}

					if cleanTestEnv || forceClean {
						if err := test.Clean(); err != nil {
							return fmt.Errorf("unable to clean test '%s' env: %w", test.Name, err)
						}
					}
				}
			}

			switch cfg.Cscli.Output {
			case "human":
				hubTestResultTable(color.Output, cfg.Cscli.Color, testResult)
			case "json":
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
					return fmt.Errorf("unable to json test result: %w", err)
				}
				fmt.Println(string(jsonStr))
			default:
				return errors.New("only human/json output modes are supported")
			}

			if !success {
				return errors.New("some tests failed")
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&noClean, "no-clean", false, "Don't clean runtime environment if test succeed")
	cmd.Flags().BoolVar(&forceClean, "clean", false, "Clean runtime environment if test fail")
	cmd.Flags().StringVar(&nucleiTargetHost, "target", hubtest.DefaultNucleiTarget, "Target for AppSec Test")
	cmd.Flags().StringVar(&appSecHost, "host", hubtest.DefaultAppsecHost, "Address to expose AppSec for hubtest")
	cmd.Flags().BoolVar(&runAll, "all", false, "Run all tests")

	return cmd
}
