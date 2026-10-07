package clihubtest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec/pkg/emoji"
	"github.com/crowdsecurity/crowdsec/pkg/hubtest"
)

func (cli *cliHubTest) run(ctx context.Context, all bool, nucleiTargetHost string, appSecHost string, args []string, maxJobs uint) error {
	cfg := cli.cfg()

	if !all && len(args) == 0 {
		return errors.New("please provide test to run or --all flag")
	}

	hubPtr.NucleiTargetHost = nucleiTargetHost
	hubPtr.AppSecHost = appSecHost

	if all {
		if err := hubPtr.LoadAllTests(); err != nil {
			return fmt.Errorf("unable to load all tests: %w", err)
		}
	} else {
		for _, testName := range args {
			_, err := hubPtr.LoadTestItem(testName)
			if err != nil {
				return fmt.Errorf("unable to load test '%s': %w", testName, err)
			}
		}
	}

	patternDir := cfg.ConfigPaths.PatternDir

	eg, gctx := errgroup.WithContext(ctx)

	if isAppsecTest {
		fmt.Fprintln(os.Stdout, "Appsec tests can not run in parallel: setting max_jobs=1")

		maxJobs = 1
	}

	eg.SetLimit(int(maxJobs))

	for _, test := range hubPtr.Tests {
		if cfg.Cscli.Output == "human" {
			fmt.Fprintf(os.Stdout, "Running test '%s'\n", test.Name)
		}

		eg.Go(func() error {
			// don't run if another goroutine failed
			select {
			case <-gctx.Done():
				return gctx.Err()
			default:
			}

			return test.Run(gctx, patternDir)
		})
	}

	return eg.Wait()
}

func (cli *cliHubTest) finalizeRun(noClean bool, forceClean bool, reportSuccess bool) error {
	cfg := cli.cfg()

	success := true
	testMap := make(map[string]*hubtest.HubTestItem)

	for _, test := range hubPtr.Tests {
		if test.AutoGen && !isAppsecTest {
			if test.ParserAssert.AutoGenAssert {
			log.Warningf("Assert file '%s' is empty, generating assertion:", test.ParserAssert.File)
				fmt.Fprintln(os.Stdout)
				fmt.Fprintln(os.Stdout, test.ParserAssert.AutoGenAssertData)
			}

			if test.ScenarioAssert.AutoGenAssert {
				log.Warningf("Assert file '%s' is empty, generating assertion:", test.ScenarioAssert.File)
				fmt.Fprintln(os.Stdout)
				fmt.Fprintln(os.Stdout, test.ScenarioAssert.AutoGenAssertData)
			}

			if !noClean {
				test.Clean()
			}

			return fmt.Errorf("please fill your assert file(s) for test '%s', exiting", test.Name)
		}

		testMap[test.Name] = test

		if test.Success {
			if !noClean {
				test.Clean()
			}
		} else {
			success = false
			cleanTestEnv := false

			if cfg.Cscli.Output == "human" {
				printParserFailures(test)
				printScenarioFailures(test)

				if !forceClean && !noClean {
					prompt := &survey.Confirm{
						Message: fmt.Sprintf("Do you want to remove runtime and result folder for '%s'?", test.Name),
						Default: true,
					}
					if err := survey.AskOne(prompt, &cleanTestEnv); err != nil {
						return fmt.Errorf("unable to ask to remove runtime folder: %w", err)
					}
				}
			}

			if cleanTestEnv || forceClean {
				test.Clean()
			}
		}
	}

	switch cfg.Cscli.Output {
	case "human":
		hubTestResultTable(color.Output, cfg.Cscli.Color, testMap, reportSuccess)
	case "json":
		jsonResult := make(map[string][]string, 0)
		jsonResult["success"] = make([]string, 0)
		jsonResult["fail"] = make([]string, 0)

		for testName, test := range testMap {
			if test.Success {
				jsonResult["success"] = append(jsonResult["success"], testName)
			} else {
				jsonResult["fail"] = append(jsonResult["fail"], testName)
			}
		}

		jsonStr, err := json.Marshal(jsonResult)
		if err != nil {
			return fmt.Errorf("unable to json test result: %w", err)
		}

		fmt.Fprintln(os.Stdout, string(jsonStr))
	default:
		return errors.New("only human/json output modes are supported")
	}

	if !success {
		if reportSuccess {
			return errors.New("some tests failed")
		}

		return errors.New("some tests failed, use --report-success to show them all")
	}

	return nil
}

func printParserFailures(test *hubtest.HubTestItem) {
	if len(test.ParserAssert.Fails) == 0 {
		return
	}

	fmt.Fprintln(os.Stdout)
	log.Errorf("Parser test '%s' failed (%d errors)\n", test.Name, len(test.ParserAssert.Fails))

	for _, fail := range test.ParserAssert.Fails {
		fmt.Fprintf(os.Stdout, "(L.%d)  %s  => %s\n", fail.Line, emoji.RedCircle, fail.Expression)
		fmt.Fprint(os.Stdout, "        Actual expression values:\n")

		for key, value := range fail.Debug {
			fmt.Fprintf(os.Stdout, "            %s = '%s'\n", key, strings.TrimSuffix(value, "\n"))
		}

		fmt.Fprintln(os.Stdout)
	}
}

func printScenarioFailures(test *hubtest.HubTestItem) {
	if len(test.ScenarioAssert.Fails) == 0 {
		return
	}

	fmt.Fprintln(os.Stdout)
	log.Errorf("Scenario test '%s' failed (%d errors)\n", test.Name, len(test.ScenarioAssert.Fails))

	for _, fail := range test.ScenarioAssert.Fails {
		fmt.Fprintf(os.Stdout, "(L.%d)  %s  => %s\n", fail.Line, emoji.RedCircle, fail.Expression)
		fmt.Fprint(os.Stdout, "        Actual expression values:\n")

		for key, value := range fail.Debug {
			fmt.Fprintf(os.Stdout, "            %s = '%s'\n", key, strings.TrimSuffix(value, "\n"))
		}

		fmt.Fprintln(os.Stdout)
	}
}

func (cli *cliHubTest) newRunCmd() *cobra.Command {
	var (
		noClean          bool
		all              bool
		reportSuccess    bool
		forceClean       bool
		nucleiTargetHost string
		appSecHost       string
	)

	maxJobs := uint(runtime.NumCPU())

	cmd := &cobra.Command{
		Use:               "run",
		Short:             "run [test_name]",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				fmt.Fprintf(os.Stdout, "Running all tests (max_jobs: %d)\n", maxJobs)
			}

			if err := cli.run(cmd.Context(), all, nucleiTargetHost, appSecHost, args, maxJobs); err != nil {
				return err
			}

			return cli.finalizeRun(noClean, forceClean, reportSuccess)
		},
	}

	cmd.Flags().BoolVar(&noClean, "no-clean", false, "Don't clean runtime environment if test succeed")
	cmd.Flags().BoolVar(&forceClean, "clean", false, "Clean runtime environment if test fail")
	cmd.Flags().StringVar(&nucleiTargetHost, "target", hubtest.DefaultNucleiTarget, "Target for AppSec Test")
	cmd.Flags().StringVar(&appSecHost, "host", hubtest.DefaultAppsecHost, "Address to expose AppSec for hubtest")
	cmd.Flags().BoolVar(&all, "all", false, "Run all tests")
	cmd.Flags().BoolVar(&reportSuccess, "report-success", false, "Report successful tests too (implied with json output)")
	cmd.Flags().UintVar(&maxJobs, "max-jobs", maxJobs, "Max number of concurrent tests (does not apply to appsec)")

	return cmd
}
