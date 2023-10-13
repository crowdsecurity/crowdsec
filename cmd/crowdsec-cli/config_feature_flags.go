package main

import (
	"fmt"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
)

func runConfigFeatureFlags(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	showRetired, err := flags.GetBool("retired")
	if err != nil {
		return err
	}

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

		fmt.Printf("%s %s", status, nameDesc)

		if feat.State == fflag.DeprecatedState {
			fmt.Printf("\n  %s %s", yellow("DEPRECATED"), feat.DeprecationMsg)
		}

		if feat.State == fflag.RetiredState {
			fmt.Printf("\n  %s %s", magenta("RETIRED"), feat.DeprecationMsg)
		}
		fmt.Println()
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
		fmt.Println(" --- Enabled features ---")
		fmt.Println()

		for _, feat := range enabled {
			printFeature(feat)
		}

		fmt.Println()
	}

	if len(disabled) > 0 {
		fmt.Println(" --- Disabled features ---")
		fmt.Println()

		for _, feat := range disabled {
			printFeature(feat)
		}

		fmt.Println()
	}

	fmt.Println("To enable a feature you can: ")
	fmt.Println("  - set the environment variable CROWDSEC_FEATURE_<uppercase_feature_name> to true")

	featurePath, err := filepath.Abs(csconfig.GetFeatureFilePath(ConfigFilePath))
	if err != nil {
		// we already read the file, shouldn't happen
		return err
	}

	fmt.Printf("  - add the line '- <feature_name>' to the file %s\n", featurePath)
	fmt.Println()

	if len(enabled) == 0 && len(disabled) == 0 {
		fmt.Println("However, no feature flag is available in this release.")
		fmt.Println()
	}

	if showRetired && len(retired) > 0 {
		fmt.Println(" --- Retired features ---")
		fmt.Println()

		for _, feat := range retired {
			printFeature(feat)
		}

		fmt.Println()
	}

	return nil
}

func NewConfigFeatureFlagsCmd() *cobra.Command {
	cmdConfigFeatureFlags := &cobra.Command{
		Use:               "feature-flags",
		Short:             "Displays feature flag status",
		Long:              `Displays the supported feature flags and their current status.`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE:              runConfigFeatureFlags,
	}

	flags := cmdConfigFeatureFlags.Flags()
	flags.Bool("retired", false, "Show retired features")

	return cmdConfigFeatureFlags
}
