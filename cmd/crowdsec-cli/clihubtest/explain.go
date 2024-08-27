package clihubtest

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/dumps"
)

func (cli *cliHubTest) NewExplainCmd() *cobra.Command {
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
						return fmt.Errorf("unable to load parser result after run: %w", err)
					}
				}

				err = test.ScenarioAssert.LoadTest(test.ScenarioResultFile, test.BucketPourResultFile)
				if err != nil {
					if err = test.Run(); err != nil {
						return fmt.Errorf("running test '%s' failed: %+v", test.Name, err)
					}

					if err = test.ScenarioAssert.LoadTest(test.ScenarioResultFile, test.BucketPourResultFile); err != nil {
						return fmt.Errorf("unable to load scenario result after run: %w", err)
					}
				}
				opts := dumps.DumpOpts{}
				dumps.DumpTree(*test.ParserAssert.TestData, *test.ScenarioAssert.PourData, opts)
			}

			return nil
		},
	}

	return cmd
}
