package cliconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/args"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
)

func (cli *cliConfig) featureFlags(showRetired bool) error {
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()

	printFeature := func(feat fflag.Feature) {
		nameDesc := feat.Name
		if feat.Description != "" {
			nameDesc += ": " + feat.Description
		}

		status := red("✗")
		if feat.IsEnabled() {
			status = green("✓")
		}

		fmt.Fprintf(os.Stdout, "%s %s", status, nameDesc)

		if feat.State == fflag.DeprecatedState {
			fmt.Fprintf(os.Stdout, "\n  %s %s", yellow("DEPRECATED"), feat.DeprecationMsg)
		}

		if feat.State == fflag.RetiredState {
			fmt.Fprintf(os.Stdout, "\n  %s %s", magenta("RETIRED"), feat.DeprecationMsg)
		}

		fmt.Fprintln(os.Stdout)
	}

	feats := fflag.Crowdsec.GetAllFeatures()

	enabled := []fflag.Feature{}
	disabled := []fflag.Feature{}
	retired := []fflag.Feature{}

	for _, feat := range feats {
		if feat.State == fflag.RetiredState {
			retired = append(retired, feat)
			continue
		}

		if feat.IsEnabled() {
			enabled = append(enabled, feat)
			continue
		}

		disabled = append(disabled, feat)
	}

	if len(enabled) > 0 {
		fmt.Fprintln(os.Stdout, " --- Enabled features ---")
		fmt.Fprintln(os.Stdout)

		for _, feat := range enabled {
			printFeature(feat)
		}

		fmt.Fprintln(os.Stdout)
	}

	if len(disabled) > 0 {
		fmt.Fprintln(os.Stdout, " --- Disabled features ---")
		fmt.Fprintln(os.Stdout)

		for _, feat := range disabled {
			printFeature(feat)
		}

		fmt.Fprintln(os.Stdout)
	}

	fmt.Fprintln(os.Stdout, "To enable a feature you can: ")
	fmt.Fprintln(os.Stdout, "  - set the environment variable CROWDSEC_FEATURE_<uppercase_feature_name> to true")

	featurePath, err := filepath.Abs(csconfig.GetFeatureFilePath(cli.cfg().FilePath))
	if err != nil {
		// we already read the file, shouldn't happen
		return err
	}

	fmt.Fprintf(os.Stdout, "  - add the line '- <feature_name>' to the file %s\n", featurePath)
	fmt.Fprintln(os.Stdout)

	if len(enabled) == 0 && len(disabled) == 0 {
		fmt.Fprintln(os.Stdout, "However, no feature flag is available in this release.")
		fmt.Fprintln(os.Stdout)
	}

	if showRetired && len(retired) > 0 {
		fmt.Fprintln(os.Stdout, " --- Retired features ---")
		fmt.Fprintln(os.Stdout)

		for _, feat := range retired {
			printFeature(feat)
		}

		fmt.Fprintln(os.Stdout)
	}

	return nil
}

func (cli *cliConfig) newFeatureFlagsCmd() *cobra.Command {
	var showRetired bool

	cmd := &cobra.Command{
		Use:               "feature-flags",
		Short:             "Displays feature flag status",
		Long:              `Displays the supported feature flags and their current status.`,
		Args:              args.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.featureFlags(showRetired)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&showRetired, "retired", false, "Show retired features")

	return cmd
}
