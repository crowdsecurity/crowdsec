package clihubtest

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/pkg/dumps"
)

func (cli *cliHubTest) explain(ctx context.Context, testName string, details bool, skipOk bool) error {
	test, err := HubTest.LoadTestItem(testName)
	if err != nil {
		return fmt.Errorf("can't load test: %w", err)
	}

	cfg := cli.cfg()
	patternDir := cfg.ConfigPaths.PatternDir

	err = test.ParserAssert.LoadTest(test.ParserResultFile)
	if err != nil {
		if err = test.Run(ctx, patternDir); err != nil {
			return fmt.Errorf("running test '%s' failed: %w", test.Name, err)
		}

		if err = test.ParserAssert.LoadTest(test.ParserResultFile); err != nil {
			return fmt.Errorf("unable to load parser result after run: %w", err)
		}
	}

	err = test.ScenarioAssert.LoadTest(test.ScenarioResultFile, test.BucketPourResultFile)
	if err != nil {
		if err = test.Run(ctx, patternDir); err != nil {
			return fmt.Errorf("running test '%s' failed: %w", test.Name, err)
		}

		if err = test.ScenarioAssert.LoadTest(test.ScenarioResultFile, test.BucketPourResultFile); err != nil {
			return fmt.Errorf("unable to load scenario result after run: %w", err)
		}
	}

	opts := dumps.DumpOpts{
		Details: details,
		SkipOk:  skipOk,
	}

	dumps.DumpTree(*test.ParserAssert.TestData, *test.ScenarioAssert.PourData, opts)

	return nil
}

func (cli *cliHubTest) newExplainCmd() *cobra.Command {
	var (
		details bool
		skipOk  bool
	)

	cmd := &cobra.Command{
		Use:               "explain",
		Short:             "explain [test_name]",
		Args:              args.MinimumNArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			for _, testName := range args {
				if err := cli.explain(ctx, testName, details, skipOk); err != nil {
					return err
				}
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&details, "verbose", "v", false, "Display individual changes")
	flags.BoolVar(&skipOk, "failures", false, "Only show failed lines")

	return cmd
}
