package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/AlecAivazis/survey/v2"
	"github.com/enescakir/emoji"
	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/hubtest"
)

var HubTest hubtest.HubTest
var HubAppsecTests hubtest.HubTest
var hubPtr *hubtest.HubTest
var isAppsecTest bool

type cliHubTest struct{}

func NewCLIHubTest() *cliHubTest {
	return &cliHubTest{}
}

func (cli cliHubTest) NewCommand() *cobra.Command {
	var hubPath string
	var crowdsecPath string
	var cscliPath string

	cmd := &cobra.Command{
		Use:               "hubtest",
		Short:             "Run functional tests on hub configurations",
		Long:              "Run functional tests on hub configurations (parsers, scenarios, collections...)",
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			var err error
			HubTest, err = hubtest.NewHubTest(hubPath, crowdsecPath, cscliPath, false)
			if err != nil {
				return fmt.Errorf("unable to load hubtest: %+v", err)
			}

			HubAppsecTests, err = hubtest.NewHubTest(hubPath, crowdsecPath, cscliPath, true)
			if err != nil {
				return fmt.Errorf("unable to load appsec specific hubtest: %+v", err)
			}
			/*commands will use the hubPtr, will point to the default hubTest object, or the one dedicated to appsec tests*/
			hubPtr = &HubTest
			if isAppsecTest {
				hubPtr = &HubAppsecTests
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&hubPath, "hub", ".", "Path to hub folder")
	cmd.PersistentFlags().StringVar(&crowdsecPath, "crowdsec", "crowdsec", "Path to crowdsec")
	cmd.PersistentFlags().StringVar(&cscliPath, "cscli", "cscli", "Path to cscli")
	cmd.PersistentFlags().BoolVar(&isAppsecTest, "appsec", false, "Command relates to appsec tests")

	cmd.AddCommand(cli.NewCreateCmd())
	cmd.AddCommand(cli.NewRunCmd())
	cmd.AddCommand(cli.NewCleanCmd())
	cmd.AddCommand(cli.NewInfoCmd())
	cmd.AddCommand(cli.NewListCmd())
	cmd.AddCommand(cli.NewCoverageCmd())
	cmd.AddCommand(cli.NewEvalCmd())
	cmd.AddCommand(cli.NewExplainCmd())

	return cmd
}

func (cli cliHubTest) NewCreateCmd() *cobra.Command {
	parsers := []string{}
	postoverflows := []string{}
	scenarios := []string{}
	var ignoreParsers bool
	var labels map[string]string
	var logType string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "create [test_name]",
		Example: `cscli hubtest create my-awesome-test --type syslog
cscli hubtest create my-nginx-custom-test --type nginx
cscli hubtest create my-scenario-test --parsers crowdsecurity/nginx --scenarios crowdsecurity/http-probing`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			testName := args[0]
			testPath := filepath.Join(hubPtr.HubTestPath, testName)
			if _, err := os.Stat(testPath); os.IsExist(err) {
				return fmt.Errorf("test '%s' already exists in '%s', exiting", testName, testPath)
			}

			if isAppsecTest {
				logType = "appsec"
			}

			if logType == "" {
				return fmt.Errorf("please provide a type (--type) for the test")
			}

			if err := os.MkdirAll(testPath, os.ModePerm); err != nil {
				return fmt.Errorf("unable to create folder '%s': %+v", testPath, err)
			}

			configFilePath := filepath.Join(testPath, "config.yaml")

			configFileData := &hubtest.HubTestItemConfig{}
			if logType == "appsec" {
				//create empty nuclei template file
				nucleiFileName := fmt.Sprintf("%s.yaml", testName)
				nucleiFilePath := filepath.Join(testPath, nucleiFileName)
				nucleiFile, err := os.OpenFile(nucleiFilePath, os.O_RDWR|os.O_CREATE, 0755)
				if err != nil {
					return err
				}

				ntpl := template.Must(template.New("nuclei").Parse(hubtest.TemplateNucleiFile))
				if ntpl == nil {
					return fmt.Errorf("unable to parse nuclei template")
				}
				ntpl.ExecuteTemplate(nucleiFile, "nuclei", struct{ TestName string }{TestName: testName})
				nucleiFile.Close()
				configFileData.AppsecRules = []string{"./appsec-rules/<author>/your_rule_here.yaml"}
				configFileData.NucleiTemplate = nucleiFileName
				fmt.Println()
				fmt.Printf("  Test name                   :  %s\n", testName)
				fmt.Printf("  Test path                   :  %s\n", testPath)
				fmt.Printf("  Config File                 :  %s\n", configFilePath)
				fmt.Printf("  Nuclei Template             :  %s\n", nucleiFilePath)
			} else {
				// create empty log file
				logFileName := fmt.Sprintf("%s.log", testName)
				logFilePath := filepath.Join(testPath, logFileName)
				logFile, err := os.Create(logFilePath)
				if err != nil {
					return err
				}
				logFile.Close()

				// create empty parser assertion file
				parserAssertFilePath := filepath.Join(testPath, hubtest.ParserAssertFileName)
				parserAssertFile, err := os.Create(parserAssertFilePath)
				if err != nil {
					return err
				}
				parserAssertFile.Close()
				// create empty scenario assertion file
				scenarioAssertFilePath := filepath.Join(testPath, hubtest.ScenarioAssertFileName)
				scenarioAssertFile, err := os.Create(scenarioAssertFilePath)
				if err != nil {
					return err
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
				configFileData.Parsers = parsers
				configFileData.Scenarios = scenarios
				configFileData.PostOverflows = postoverflows
				configFileData.LogFile = logFileName
				configFileData.LogType = logType
				configFileData.IgnoreParsers = ignoreParsers
				configFileData.Labels = labels
				fmt.Println()
				fmt.Printf("  Test name                   :  %s\n", testName)
				fmt.Printf("  Test path                   :  %s\n", testPath)
				fmt.Printf("  Log file                    :  %s (please fill it with logs)\n", logFilePath)
				fmt.Printf("  Parser assertion file       :  %s (please fill it with assertion)\n", parserAssertFilePath)
				fmt.Printf("  Scenario assertion file     :  %s (please fill it with assertion)\n", scenarioAssertFilePath)
				fmt.Printf("  Configuration File          :  %s (please fill it with parsers, scenarios...)\n", configFilePath)

			}

			fd, err := os.Create(configFilePath)
			if err != nil {
				return fmt.Errorf("open: %s", err)
			}
			data, err := yaml.Marshal(configFileData)
			if err != nil {
				return fmt.Errorf("marshal: %s", err)
			}
			_, err = fd.Write(data)
			if err != nil {
				return fmt.Errorf("write: %s", err)
			}
			if err := fd.Close(); err != nil {
				return fmt.Errorf("close: %s", err)
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&logType, "type", "t", "", "Log type of the test")
	cmd.Flags().StringSliceVarP(&parsers, "parsers", "p", parsers, "Parsers to add to test")
	cmd.Flags().StringSliceVar(&postoverflows, "postoverflows", postoverflows, "Postoverflows to add to test")
	cmd.Flags().StringSliceVarP(&scenarios, "scenarios", "s", scenarios, "Scenarios to add to test")
	cmd.PersistentFlags().BoolVar(&ignoreParsers, "ignore-parsers", false, "Don't run test on parsers")

	return cmd
}

func (cli cliHubTest) NewRunCmd() *cobra.Command {
	var noClean bool
	var runAll bool
	var forceClean bool
	var NucleiTargetHost string
	var AppSecHost string
	var cmd = &cobra.Command{
		Use:               "run",
		Short:             "run [test_name]",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !runAll && len(args) == 0 {
				printHelp(cmd)
				return fmt.Errorf("please provide test to run or --all flag")
			}
			hubPtr.NucleiTargetHost = NucleiTargetHost
			hubPtr.AppSecHost = AppSecHost
			if runAll {
				if err := hubPtr.LoadAllTests(); err != nil {
					return fmt.Errorf("unable to load all tests: %+v", err)
				}
			} else {
				for _, testName := range args {
					_, err := hubPtr.LoadTestItem(testName)
					if err != nil {
						return fmt.Errorf("unable to load test '%s': %s", testName, err)
					}
				}
			}

			// set timezone to avoid DST issues
			os.Setenv("TZ", "UTC")
			for _, test := range hubPtr.Tests {
				if csConfig.Cscli.Output == "human" {
					log.Infof("Running test '%s'", test.Name)
				}
				err := test.Run()
				if err != nil {
					log.Errorf("running test '%s' failed: %+v", test.Name, err)
				}
			}

			return nil
		},
		PersistentPostRunE: func(_ *cobra.Command, _ []string) error {
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
							return fmt.Errorf("unable to clean test '%s' env: %s", test.Name, err)
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
							return fmt.Errorf("unable to clean test '%s' env: %s", test.Name, err)
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
								return fmt.Errorf("unable to ask to remove runtime folder: %s", err)
							}
						}
					}

					if cleanTestEnv || forceClean {
						if err := test.Clean(); err != nil {
							return fmt.Errorf("unable to clean test '%s' env: %s", test.Name, err)
						}
					}
				}
			}

			switch csConfig.Cscli.Output {
			case "human":
				hubTestResultTable(color.Output, testResult)
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
					return fmt.Errorf("unable to json test result: %s", err)
				}
				fmt.Println(string(jsonStr))
			default:
				return fmt.Errorf("only human/json output modes are supported")
			}

			if !success {
				os.Exit(1)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&noClean, "no-clean", false, "Don't clean runtime environment if test succeed")
	cmd.Flags().BoolVar(&forceClean, "clean", false, "Clean runtime environment if test fail")
	cmd.Flags().StringVar(&NucleiTargetHost, "target", hubtest.DefaultNucleiTarget, "Target for AppSec Test")
	cmd.Flags().StringVar(&AppSecHost, "host", hubtest.DefaultAppsecHost, "Address to expose AppSec for hubtest")
	cmd.Flags().BoolVar(&runAll, "all", false, "Run all tests")

	return cmd
}

func (cli cliHubTest) NewCleanCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:               "clean",
		Short:             "clean [test_name]",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			for _, testName := range args {
				test, err := hubPtr.LoadTestItem(testName)
				if err != nil {
					return fmt.Errorf("unable to load test '%s': %s", testName, err)
				}
				if err := test.Clean(); err != nil {
					return fmt.Errorf("unable to clean test '%s' env: %s", test.Name, err)
				}
			}

			return nil
		},
	}

	return cmd
}

func (cli cliHubTest) NewInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "info",
		Short:             "info [test_name]",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			for _, testName := range args {
				test, err := hubPtr.LoadTestItem(testName)
				if err != nil {
					return fmt.Errorf("unable to load test '%s': %s", testName, err)
				}
				fmt.Println()
				fmt.Printf("  Test name                   :  %s\n", test.Name)
				fmt.Printf("  Test path                   :  %s\n", test.Path)
				if isAppsecTest {
					fmt.Printf("  Nuclei Template             :  %s\n", test.Config.NucleiTemplate)
					fmt.Printf("  Appsec Rules                  :  %s\n", strings.Join(test.Config.AppsecRules, ", "))
				} else {
					fmt.Printf("  Log file                    :  %s\n", filepath.Join(test.Path, test.Config.LogFile))
					fmt.Printf("  Parser assertion file       :  %s\n", filepath.Join(test.Path, hubtest.ParserAssertFileName))
					fmt.Printf("  Scenario assertion file     :  %s\n", filepath.Join(test.Path, hubtest.ScenarioAssertFileName))
				}
				fmt.Printf("  Configuration File          :  %s\n", filepath.Join(test.Path, "config.yaml"))
			}

			return nil
		},
	}

	return cmd
}

func (cli cliHubTest) NewListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "list",
		Short:             "list",
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := hubPtr.LoadAllTests(); err != nil {
				return fmt.Errorf("unable to load all tests: %s", err)
			}

			switch csConfig.Cscli.Output {
			case "human":
				hubTestListTable(color.Output, hubPtr.Tests)
			case "json":
				j, err := json.MarshalIndent(hubPtr.Tests, " ", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(j))
			default:
				return fmt.Errorf("only human/json output modes are supported")
			}

			return nil
		},
	}

	return cmd
}

func (cli cliHubTest) NewCoverageCmd() *cobra.Command {
	var showParserCov bool
	var showScenarioCov bool
	var showOnlyPercent bool
	var showAppsecCov bool

	cmd := &cobra.Command{
		Use:               "coverage",
		Short:             "coverage",
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			//for this one we explicitly don't do for appsec
			if err := HubTest.LoadAllTests(); err != nil {
				return fmt.Errorf("unable to load all tests: %+v", err)
			}
			var err error
			scenarioCoverage := []hubtest.Coverage{}
			parserCoverage := []hubtest.Coverage{}
			appsecRuleCoverage := []hubtest.Coverage{}
			scenarioCoveragePercent := 0
			parserCoveragePercent := 0
			appsecRuleCoveragePercent := 0

			// if both are false (flag by default), show both
			showAll := !showScenarioCov && !showParserCov && !showAppsecCov

			if showParserCov || showAll {
				parserCoverage, err = HubTest.GetParsersCoverage()
				if err != nil {
					return fmt.Errorf("while getting parser coverage: %s", err)
				}
				parserTested := 0
				for _, test := range parserCoverage {
					if test.TestsCount > 0 {
						parserTested++
					}
				}
				parserCoveragePercent = int(math.Round((float64(parserTested) / float64(len(parserCoverage)) * 100)))
			}

			if showScenarioCov || showAll {
				scenarioCoverage, err = HubTest.GetScenariosCoverage()
				if err != nil {
					return fmt.Errorf("while getting scenario coverage: %s", err)
				}

				scenarioTested := 0
				for _, test := range scenarioCoverage {
					if test.TestsCount > 0 {
						scenarioTested++
					}
				}

				scenarioCoveragePercent = int(math.Round((float64(scenarioTested) / float64(len(scenarioCoverage)) * 100)))
			}

			if showAppsecCov || showAll {
				appsecRuleCoverage, err = HubTest.GetAppsecCoverage()
				if err != nil {
					return fmt.Errorf("while getting scenario coverage: %s", err)
				}

				appsecRuleTested := 0
				for _, test := range appsecRuleCoverage {
					if test.TestsCount > 0 {
						appsecRuleTested++
					}
				}
				appsecRuleCoveragePercent = int(math.Round((float64(appsecRuleTested) / float64(len(appsecRuleCoverage)) * 100)))
			}

			if showOnlyPercent {
				if showAll {
					fmt.Printf("parsers=%d%%\nscenarios=%d%%\nappsec_rules=%d%%", parserCoveragePercent, scenarioCoveragePercent, appsecRuleCoveragePercent)
				} else if showParserCov {
					fmt.Printf("parsers=%d%%", parserCoveragePercent)
				} else if showScenarioCov {
					fmt.Printf("scenarios=%d%%", scenarioCoveragePercent)
				} else if showAppsecCov {
					fmt.Printf("appsec_rules=%d%%", appsecRuleCoveragePercent)
				}
				os.Exit(0)
			}

			switch csConfig.Cscli.Output {
			case "human":
				if showParserCov || showAll {
					hubTestParserCoverageTable(color.Output, parserCoverage)
				}

				if showScenarioCov || showAll {
					hubTestScenarioCoverageTable(color.Output, scenarioCoverage)
				}

				if showAppsecCov || showAll {
					hubTestAppsecRuleCoverageTable(color.Output, appsecRuleCoverage)
				}

				fmt.Println()
				if showParserCov || showAll {
					fmt.Printf("PARSERS    : %d%% of coverage\n", parserCoveragePercent)
				}
				if showScenarioCov || showAll {
					fmt.Printf("SCENARIOS  : %d%% of coverage\n", scenarioCoveragePercent)
				}
				if showAppsecCov || showAll {
					fmt.Printf("APPSEC RULES  : %d%% of coverage\n", appsecRuleCoveragePercent)
				}
			case "json":
				dump, err := json.MarshalIndent(parserCoverage, "", " ")
				if err != nil {
					return err
				}
				fmt.Printf("%s", dump)
				dump, err = json.MarshalIndent(scenarioCoverage, "", " ")
				if err != nil {
					return err
				}
				fmt.Printf("%s", dump)
				dump, err = json.MarshalIndent(appsecRuleCoverage, "", " ")
				if err != nil {
					return err
				}
				fmt.Printf("%s", dump)
			default:
				return fmt.Errorf("only human/json output modes are supported")
			}

			return nil
		},
	}

	cmd.PersistentFlags().BoolVar(&showOnlyPercent, "percent", false, "Show only percentages of coverage")
	cmd.PersistentFlags().BoolVar(&showParserCov, "parsers", false, "Show only parsers coverage")
	cmd.PersistentFlags().BoolVar(&showScenarioCov, "scenarios", false, "Show only scenarios coverage")
	cmd.PersistentFlags().BoolVar(&showAppsecCov, "appsec", false, "Show only appsec coverage")

	return cmd
}

func (cli cliHubTest) NewEvalCmd() *cobra.Command {
	var evalExpression string

	cmd := &cobra.Command{
		Use:               "eval",
		Short:             "eval [test_name]",
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			for _, testName := range args {
				test, err := hubPtr.LoadTestItem(testName)
				if err != nil {
					return fmt.Errorf("can't load test: %+v", err)
				}

				err = test.ParserAssert.LoadTest(test.ParserResultFile)
				if err != nil {
					return fmt.Errorf("can't load test results from '%s': %+v", test.ParserResultFile, err)
				}

				output, err := test.ParserAssert.EvalExpression(evalExpression)
				if err != nil {
					return err
				}

				fmt.Print(output)
			}

			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&evalExpression, "expr", "e", "", "Expression to eval")

	return cmd
}

func (cli cliHubTest) NewExplainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "explain",
		Short:             "explain [test_name]",
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			for _, testName := range args {
				test, err := HubTest.LoadTestItem(testName)
				if err != nil {
					return fmt.Errorf("can't load test: %+v", err)
				}
				err = test.ParserAssert.LoadTest(test.ParserResultFile)
				if err != nil {
					if err = test.Run(); err != nil {
						return fmt.Errorf("running test '%s' failed: %+v", test.Name, err)
					}

					if err = test.ParserAssert.LoadTest(test.ParserResultFile); err != nil {
						return fmt.Errorf("unable to load parser result after run: %s", err)
					}
				}

				err = test.ScenarioAssert.LoadTest(test.ScenarioResultFile, test.BucketPourResultFile)
				if err != nil {
					if err = test.Run(); err != nil {
						return fmt.Errorf("running test '%s' failed: %+v", test.Name, err)
					}

					if err = test.ScenarioAssert.LoadTest(test.ScenarioResultFile, test.BucketPourResultFile); err != nil {
						return fmt.Errorf("unable to load scenario result after run: %s", err)
					}
				}
				opts := hubtest.DumpOpts{}
				hubtest.DumpTree(*test.ParserAssert.TestData, *test.ScenarioAssert.PourData, opts)
			}

			return nil
		},
	}

	return cmd
}
