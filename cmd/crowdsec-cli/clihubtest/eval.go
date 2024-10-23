package clihubtest

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (cli *cliHubTest) newEvalCmd() *cobra.Command {
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
