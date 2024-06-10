package main

import (
	"bytes"
	"context"
	"errors"
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

type cliSetup struct {
	cfg configGetter
}

func NewCLISetup(cfg configGetter) *cliSetup {
	return &cliSetup{
		cfg: cfg,
	}
}

func (cli *cliSetup) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "setup",
		Short:             "Tools to configure crowdsec",
		Long:              "Manage hub configuration and service detection",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(cli.NewDetectCmd())
	cmd.AddCommand(cli.NewInstallHubCmd())
	cmd.AddCommand(cli.NewDataSourcesCmd())
	cmd.AddCommand(cli.NewValidateCmd())

	return cmd
}

type detectFlags struct {
	detectConfigFile      string
	listSupportedServices bool
	forcedUnits           []string
	forcedProcesses       []string
	forcedOSFamily        string
	forcedOSID            string
	forcedOSVersion       string
	skipServices          []string
	snubSystemd           bool
	outYaml               bool
}

func (f *detectFlags) bind(cmd *cobra.Command) {
	defaultServiceDetect := csconfig.DefaultConfigPath("hub", "detect.yaml")

	flags := cmd.Flags()
	flags.StringVar(&f.detectConfigFile, "detect-config", defaultServiceDetect, "path to service detection configuration")
	flags.BoolVar(&f.listSupportedServices, "list-supported-services", false, "do not detect; only print supported services")
	flags.StringSliceVar(&f.forcedUnits, "force-unit", nil, "force detection of a systemd unit (can be repeated)")
	flags.StringSliceVar(&f.forcedProcesses, "force-process", nil, "force detection of a running process (can be repeated)")
	flags.StringSliceVar(&f.skipServices, "skip-service", nil, "ignore a service, don't recommend hub/datasources (can be repeated)")
	flags.StringVar(&f.forcedOSFamily, "force-os-family", "", "override OS.Family: one of linux, freebsd, windows or darwin")
	flags.StringVar(&f.forcedOSID, "force-os-id", "", "override OS.ID=[debian | ubuntu | , redhat...]")
	flags.StringVar(&f.forcedOSVersion, "force-os-version", "", "override OS.RawVersion (of OS or Linux distribution)")
	flags.BoolVar(&f.snubSystemd, "snub-systemd", false, "don't use systemd, even if available")
	flags.BoolVar(&f.outYaml, "yaml", false, "output yaml, not json")
}

func (cli *cliSetup) NewDetectCmd() *cobra.Command {
	f := detectFlags{}

	cmd := &cobra.Command{
		Use:               "detect",
		Short:             "detect running services, generate a setup file",
		DisableAutoGenTag: true,
		RunE:              func(_ *cobra.Command, args []string) error {
			return cli.detect(f)
		},
	}

	f.bind(cmd)
	return cmd
}

func (cli *cliSetup) NewInstallHubCmd() *cobra.Command {
	var dryRun bool

	cmd := &cobra.Command{
		Use:               "install-hub [setup_file] [flags]",
		Short:             "install items from a setup file",
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE:              func(cmd *cobra.Command, args []string) error {
			return cli.install(cmd.Context(), dryRun, args[0])
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&dryRun, "dry-run", false, "don't install anything; print out what would have been")

	return cmd
}

func (cli *cliSetup) NewDataSourcesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "datasources [setup_file] [flags]",
		Short:             "generate datasource (acquisition) configuration from a setup file",
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE:              runSetupDataSources,
	}

	flags := cmd.Flags()
	flags.String("to-dir", "", "write the configuration to a directory, in multiple files")

	return cmd
}

func (cli *cliSetup) NewValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "validate [setup_file]",
		Short:             "validate a setup file",
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE:              runSetupValidate,
	}

	return cmd
}

func (cli *cliSetup) detect(f detectFlags) error {
	var (
		detectReader *os.File
		err          error
	)

	switch f.detectConfigFile {
	case "-":
		log.Tracef("Reading detection rules from stdin")

		detectReader = os.Stdin
	default:
		log.Tracef("Reading detection rules: %s", f.detectConfigFile)

		detectReader, err = os.Open(f.detectConfigFile)
		if err != nil {
			return err
		}
	}

	if !f.snubSystemd {
		_, err := exec.LookPath("systemctl")
		if err != nil {
			log.Debug("systemctl not available: snubbing systemd")

			f.snubSystemd = true
		}
	}

	if f.forcedOSFamily == "" && f.forcedOSID != "" {
		log.Debug("force-os-id is set: force-os-family defaults to 'linux'")

		f.forcedOSFamily = "linux"
	}

	if f.listSupportedServices {
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
		ForcedUnits:     f.forcedUnits,
		ForcedProcesses: f.forcedProcesses,
		ForcedOS: setup.ExprOS{
			Family:     f.forcedOSFamily,
			ID:         f.forcedOSID,
			RawVersion: f.forcedOSVersion,
		},
		SkipServices: f.skipServices,
		SnubSystemd:  f.snubSystemd,
	}

	hubSetup, err := setup.Detect(detectReader, opts)
	if err != nil {
		return fmt.Errorf("detecting services: %w", err)
	}

	setup, err := setupAsString(hubSetup, f.outYaml)
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

func (cli *cliSetup) install(ctx context.Context, dryRun bool, fromFile string) error {
	input, err := os.ReadFile(fromFile)
	if err != nil {
		return fmt.Errorf("while reading file %s: %w", fromFile, err)
	}

	cfg := cli.cfg()

	hub, err := require.Hub(cfg, require.RemoteHub(ctx, cfg), log.StandardLogger())
	if err != nil {
		return err
	}

	return setup.InstallHubItems(ctx, hub, input, dryRun)
}

func runSetupValidate(cmd *cobra.Command, args []string) error {
	fromFile := args[0]

	input, err := os.ReadFile(fromFile)
	if err != nil {
		return fmt.Errorf("while reading stdin: %w", err)
	}

	if err = setup.Validate(input); err != nil {
		fmt.Printf("%v\n", err)
		return errors.New("invalid setup file")
	}

	return nil
}
