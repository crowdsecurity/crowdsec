package args

import (
	"fmt"

	"github.com/spf13/cobra"
)

// MinimumNArgs is a drop-in replacement for cobra.MinimumNArgs that prints the usage in case of wrong number of arguments, but not other errors.
func MinimumNArgs(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) < n {
			_ = cmd.Help()
			fmt.Fprintln(cmd.OutOrStdout(), "")
			return fmt.Errorf("requires at least %d arg(s), only received %d", n, len(args))
		}
		return nil
	}
}

// MaximumNArgs is a drop-in replacement for cobra.MaximumNArgs that prints the usage in case of wrong number of arguments, but not other errors.
func MaximumNArgs(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) > n {
			_ = cmd.Help()
			fmt.Fprintln(cmd.OutOrStdout(), "")
			return fmt.Errorf("accepts at most %d arg(s), received %d", n, len(args))
		}
		return nil
	}
}

// ExactArgs is a drop-in replacement for cobra.ExactArgs that prints the usage in case of wrong number of arguments, but not other errors.
func ExactArgs(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != n {
			_ = cmd.Help()
			fmt.Fprintln(cmd.OutOrStdout(), "")
			return fmt.Errorf("accepts %d arg(s), received %d", n, len(args))
		}
		return nil
	}
}

// NoArgs is a drop-in replacement for cobra.NoArgs that prints the usage in case of wrong number of arguments, but not other errors.
func NoArgs(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		_ = cmd.Help()
		fmt.Fprintln(cmd.OutOrStdout(), "")
		return fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())
	}
	return nil
}

