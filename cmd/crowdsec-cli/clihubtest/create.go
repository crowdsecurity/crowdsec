package clihubtest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/hubtest"
)

func (cli *cliHubTest) newCreateCmd() *cobra.Command {
	var (
		ignoreParsers bool
		labels        map[string]string
		logType       string
	)

	parsers := []string{}
	postoverflows := []string{}
	scenarios := []string{}

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
				return errors.New("please provide a type (--type) for the test")
			}

			if err := os.MkdirAll(testPath, os.ModePerm); err != nil {
				return fmt.Errorf("unable to create folder '%s': %+v", testPath, err)
			}

			configFilePath := filepath.Join(testPath, "config.yaml")

			configFileData := &hubtest.HubTestItemConfig{}
			if logType == "appsec" {
				// create empty nuclei template file
				nucleiFileName := testName + ".yaml"
				nucleiFilePath := filepath.Join(testPath, nucleiFileName)

				nucleiFile, err := os.OpenFile(nucleiFilePath, os.O_RDWR|os.O_CREATE, 0o755)
				if err != nil {
					return err
				}

				ntpl := template.Must(template.New("nuclei").Parse(hubtest.TemplateNucleiFile))
				if ntpl == nil {
					return errors.New("unable to parse nuclei template")
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
				logFileName := testName + ".log"
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
				return fmt.Errorf("open: %w", err)
			}
			data, err := yaml.Marshal(configFileData)
			if err != nil {
				return fmt.Errorf("serialize: %w", err)
			}
			_, err = fd.Write(data)
			if err != nil {
				return fmt.Errorf("write: %w", err)
			}
			if err := fd.Close(); err != nil {
				return fmt.Errorf("close: %w", err)
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
