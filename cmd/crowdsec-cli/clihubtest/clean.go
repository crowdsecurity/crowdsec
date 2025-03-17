package clihubtest

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/hubtest"
)

func (cli *cliHubTest) newCleanCmd() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:               "clean",
		Short:             "clean [test_name]",
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, args []string) error {
			if !all && len(args) == 0 {
				return errors.New("please provide test to run or --all flag")
			}

			fmt.Println("Cleaning test data...")

			tests := []*hubtest.HubTestItem{}

			if all {
				if err := hubPtr.LoadAllTests(); err != nil {
					return fmt.Errorf("unable to load all tests: %w", err)
				}

				tests = hubPtr.Tests
			} else {
				for _, testName := range args {
					test, err := hubPtr.LoadTestItem(testName)
					if err != nil {
						return fmt.Errorf("unable to load test '%s': %w", testName, err)
					}
					tests = append(tests, test)
				}
			}

			for _, test := range tests {
				test.Clean()
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "Run all tests")

	return cmd
}
