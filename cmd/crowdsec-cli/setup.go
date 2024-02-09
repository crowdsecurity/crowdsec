package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	goccyyaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/setup"
)

// NewSetupCmd defines the "cscli setup" command.
func NewSetupCmd() *cobra.Command {
	cmdSetup := &cobra.Command{
		Use:               "setup",
		Short:             "Tools to configure crowdsec",
		Long:              "Manage hub configuration and service detection",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
	}

	//
	// cscli setup detect
	//
	{
		cmdSetupDetect := &cobra.Command{
			Use:               "detect",
			Short:             "detect running services, generate a setup file",
			DisableAutoGenTag: true,
			RunE:              runSetupDetect,
		}

		defaultServiceDetect := csconfig.DefaultConfigPath("hub", "detect.yaml")

		flags := cmdSetupDetect.Flags()
		flags.String("detect-config", defaultServiceDetect, "path to service detection configuration")
		flags.Bool("list-supported-services", false, "do not detect; only print supported services")
		flags.StringSlice("force-unit", nil, "force detection of a systemd unit (can be repeated)")
		flags.StringSlice("force-process", nil, "force detection of a running process (can be repeated)")
		flags.StringSlice("skip-service", nil, "ignore a service, don't recommend hub/datasources (can be repeated)")
		flags.String("force-os-family", "", "override OS.Family: one of linux, freebsd, windows or darwin")
		flags.String("force-os-id", "", "override OS.ID=[debian | ubuntu | , redhat...]")
		flags.String("force-os-version", "", "override OS.RawVersion (of OS or Linux distribution)")
		flags.Bool("snub-systemd", false, "don't use systemd, even if available")
		flags.Bool("yaml", false, "output yaml, not json")
		cmdSetup.AddCommand(cmdSetupDetect)
	}

	//
	// cscli setup install-hub
	//
	{
		cmdSetupInstallHub := &cobra.Command{
			Use:               "install-hub [setup_file] [flags]",
			Short:             "install items from a setup file",
			Args:              cobra.ExactArgs(1),
			DisableAutoGenTag: true,
			RunE:              runSetupInstallHub,
		}

		flags := cmdSetupInstallHub.Flags()
		flags.Bool("dry-run", false, "don't install anything; print out what would have been")
		cmdSetup.AddCommand(cmdSetupInstallHub)
	}

	//
	// cscli setup datasources
	//
	{
		cmdSetupDataSources := &cobra.Command{
			Use:               "datasources [setup_file] [flags]",
			Short:             "generate datasource (acquisition) configuration from a setup file",
			Args:              cobra.ExactArgs(1),
			DisableAutoGenTag: true,
			RunE:              runSetupDataSources,
		}

		flags := cmdSetupDataSources.Flags()
		flags.String("to-dir", "", "write the configuration to a directory, in multiple files")
		cmdSetup.AddCommand(cmdSetupDataSources)
	}

	//
	// cscli setup validate
	//
	{
		cmdSetupValidate := &cobra.Command{
			Use:               "validate [setup_file]",
			Short:             "validate a setup file",
			Args:              cobra.ExactArgs(1),
			DisableAutoGenTag: true,
			RunE:              runSetupValidate,
		}

		cmdSetup.AddCommand(cmdSetupValidate)
	}

	return cmdSetup
}

func runSetupDetect(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	detectConfigFile, err := flags.GetString("detect-config")
	if err != nil {
		return err
	}

	var detectReader *os.File

	switch detectConfigFile {
	case "-":
		log.Tracef("Reading detection rules from stdin")
		detectReader = os.Stdin
	default:
		log.Tracef("Reading detection rules: %s", detectConfigFile)
		detectReader, err = os.Open(detectConfigFile)
		if err != nil {
			return err
		}
	}

	listSupportedServices, err := flags.GetBool("list-supported-services")
	if err != nil {
		return err
	}

	forcedUnits, err := flags.GetStringSlice("force-unit")
	if err != nil {
		return err
	}

	forcedProcesses, err := flags.GetStringSlice("force-process")
	if err != nil {
		return err
	}

	forcedOSFamily, err := flags.GetString("force-os-family")
	if err != nil {
		return err
	}

	forcedOSID, err := flags.GetString("force-os-id")
	if err != nil {
		return err
	}

	forcedOSVersion, err := flags.GetString("force-os-version")
	if err != nil {
		return err
	}

	skipServices, err := flags.GetStringSlice("skip-service")
	if err != nil {
		return err
	}

	snubSystemd, err := flags.GetBool("snub-systemd")
	if err != nil {
		return err
	}

	if !snubSystemd {
		_, err := exec.LookPath("systemctl")
		if err != nil {
			log.Debug("systemctl not available: snubbing systemd")
			snubSystemd = true
		}
	}

	outYaml, err := flags.GetBool("yaml")
	if err != nil {
		return err
	}

	if forcedOSFamily == "" && forcedOSID != "" {
		log.Debug("force-os-id is set: force-os-family defaults to 'linux'")
		forcedOSFamily = "linux"
	}

	if listSupportedServices {
		supported, err := setup.ListSupported(detectReader)
		if err != nil {
			return err
		}

		for _, svc := range supported {
			fmt.Println(svc)
		}

		return nil
	}

	opts := setup.DetectOptions{
		ForcedUnits:     forcedUnits,
		ForcedProcesses: forcedProcesses,
		ForcedOS: setup.ExprOS{
			Family:     forcedOSFamily,
			ID:         forcedOSID,
			RawVersion: forcedOSVersion,
		},
		SkipServices: skipServices,
		SnubSystemd:  snubSystemd,
	}

	hubSetup, err := setup.Detect(detectReader, opts)
	if err != nil {
		return fmt.Errorf("detecting services: %w", err)
	}

	setup, err := setupAsString(hubSetup, outYaml)
	if err != nil {
		return err
	}
	fmt.Println(setup)

	return nil
}

func setupAsString(cs setup.Setup, outYaml bool) (string, error) {
	var (
		ret []byte
		err error
	)

	wrap := func(err error) error {
		return fmt.Errorf("while marshaling setup: %w", err)
	}

	indentLevel := 2
	buf := &bytes.Buffer{}
	enc := yaml.NewEncoder(buf)
	enc.SetIndent(indentLevel)

	if err = enc.Encode(cs); err != nil {
		return "", wrap(err)
	}

	if err = enc.Close(); err != nil {
		return "", wrap(err)
	}

	ret = buf.Bytes()

	if !outYaml {
		// take a general approach to output json, so we avoid the
		// double tags in the structures and can use go-yaml features
		// missing from the json package
		ret, err = goccyyaml.YAMLToJSON(ret)
		if err != nil {
			return "", wrap(err)
		}
	}

	return string(ret), nil
}

func runSetupDataSources(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	fromFile := args[0]

	toDir, err := flags.GetString("to-dir")
	if err != nil {
		return err
	}

	input, err := os.ReadFile(fromFile)
	if err != nil {
		return fmt.Errorf("while reading setup file: %w", err)
	}

	output, err := setup.DataSources(input, toDir)
	if err != nil {
		return err
	}

	if toDir == "" {
		fmt.Println(output)
	}

	return nil
}

func runSetupInstallHub(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	fromFile := args[0]

	dryRun, err := flags.GetBool("dry-run")
	if err != nil {
		return err
	}

	input, err := os.ReadFile(fromFile)
	if err != nil {
		return fmt.Errorf("while reading file %s: %w", fromFile, err)
	}

	hub, err := require.Hub(csConfig, require.RemoteHub(csConfig), log.StandardLogger())
	if err != nil {
		return err
	}

	if err = setup.InstallHubItems(hub, input, dryRun); err != nil {
		return err
	}

	return nil
}

func runSetupValidate(cmd *cobra.Command, args []string) error {
	fromFile := args[0]
	input, err := os.ReadFile(fromFile)
	if err != nil {
		return fmt.Errorf("while reading stdin: %w", err)
	}

	if err = setup.Validate(input); err != nil {
		fmt.Printf("%v\n", err)
		return fmt.Errorf("invalid setup file")
	}

	return nil
}
