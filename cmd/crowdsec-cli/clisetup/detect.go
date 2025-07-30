package clisetup

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clisetup/setup"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

// detectFlags are reused for "unattended" and "interactive"
type detectFlags struct {
	detectConfigFile string
	forcedUnits      []string
	forcedProcesses  []string
	forcedOSFamily   string
	forcedOSID       string
	forcedOSVersion  string
	skipServices     []string
	skipSystemd      bool
}

func (f *detectFlags) detectConfig() (*setup.DetectConfig, string, error) {
	detectReader, err := maybeStdinFile(f.detectConfigFile)
	if err != nil {
		return nil, "", err
	}

	rulesFrom := f.detectConfigFile

	if detectReader == os.Stdin {
		rulesFrom = "<stdin>"
	}

	detectConfig, err := setup.NewDetectConfig(detectReader)
	if err != nil {
		return nil, "", fmt.Errorf("parsing %s: %w", rulesFrom, err)
	}

	return detectConfig, rulesFrom, nil
}

func (f *detectFlags) bind(cmd *cobra.Command) {
	defaultServiceDetect := os.Getenv("CROWDSEC_SETUP_DETECT_CONFIG")
	if defaultServiceDetect == "" {
		defaultServiceDetect = csconfig.DefaultConfigPath("detect.yaml")
	}

	flags := cmd.Flags()
	flags.StringVar(&f.detectConfigFile, "detect-config", defaultServiceDetect, "path to service detection configuration, will use $CROWDSEC_SETUP_DETECT_CONFIG if defined")
	flags.StringSliceVar(&f.forcedUnits, "force-unit", nil, "force detection of a systemd unit (can be repeated)")
	flags.StringSliceVar(&f.forcedProcesses, "force-process", nil, "force detection of a running process (can be repeated)")
	flags.StringSliceVar(&f.skipServices, "skip-service", nil, "ignore a service, don't recommend hub/datasources (can be repeated)")
	flags.StringVar(&f.forcedOSFamily, "force-os-family", "", "override OS.Family: one of linux, freebsd, windows or darwin")
	flags.StringVar(&f.forcedOSID, "force-os-id", "", "override OS.ID=[debian | ubuntu | redhat...]")
	flags.StringVar(&f.forcedOSVersion, "force-os-version", "", "override OS.RawVersion (of OS or Linux distribution)")
	flags.BoolVar(&f.skipSystemd, "skip-systemd", false, "don't use systemd, even if available")

	flags.SortFlags = false
}

func (f *detectFlags) toDetectOptions(logger *logrus.Logger) setup.DetectOptions {
	if !f.skipSystemd {
		if _, err := exec.LookPath("systemctl"); err != nil {
			logger.Debug("systemctl not available: skipping systemd detection")

			f.skipSystemd = true
		}
	}

	if f.forcedOSFamily == "" && f.forcedOSID != "" {
		logger.Debug("force-os-id is set: force-os-family defaults to 'linux'")

		f.forcedOSFamily = "linux"
	}

	return setup.DetectOptions{
		ForcedUnits:     f.forcedUnits,
		ForcedProcesses: f.forcedProcesses,
		ForcedOS: setup.ExprOS{
			Family:     f.forcedOSFamily,
			ID:         f.forcedOSID,
			RawVersion: f.forcedOSVersion,
		},
		SkipServices: f.skipServices,
		SkipSystemd:  f.skipSystemd,
	}
}

func (cli *cliSetup) newDetectCmd() *cobra.Command {
	f := detectFlags{}

	var (
		outYaml               bool
		listSupportedServices bool
	)

	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Detect installed services and generate a setup file",
		Long: `Detects the services installed on the machine and builds a specification
to be used with the "setup install-*" commands.

You can force the detection of specific processes or units, or override OS information
using command-line flags.`,
		Example: `# detect services and print the setup plan
cscli setup detect

# force yaml instead of json (easier to edit)
cscli setup detect --yaml

# pretend that a process named "nginx" is running
cscli setup detect --force-process nginx

# pretend that a systemd unit named "some.service" is running
cscli setup detect --force-unit some.service

# detect and skip certain services
cscli setup detect --skip-service whitelists

# override the OS family
cscli setup detect --force-os-family freebsd
`,
		Args:              args.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			detectConfig, rulesFrom, err := f.detectConfig()
			if err != nil {
				return err
			}

			if listSupportedServices {
				for _, svc := range detectConfig.ListSupportedServices() {
					fmt.Fprintln(os.Stdout, svc)
				}

				return nil
			}

			logger := logrus.StandardLogger()

			units := setup.UnitMap{}

			if !f.skipSystemd {
				if units, err = setup.DetectSystemdUnits(ctx, exec.CommandContext, f.forcedUnits); err != nil {
					return err
				}
			}

			procs, err := setup.DetectProcesses(ctx, f.forcedProcesses, logger)
			if err != nil {
				return err
			}

			stup, err := setup.BuildSetup(ctx, detectConfig, f.toDetectOptions(logger),
				setup.OSExprPath{},
				units,
				procs, logger)
			if err != nil {
				return fmt.Errorf("parsing %s: %w", rulesFrom, err)
			}

			yamlBytes, err := stup.ToYAML(outYaml)
			if err != nil {
				return fmt.Errorf("while serializing setup: %w", err)
			}

			fmt.Fprintln(os.Stdout, string(yamlBytes))

			return nil
		},
	}

	f.bind(cmd)

	flags := cmd.Flags()
	flags.BoolVar(&outYaml, "yaml", false, "output yaml, not json")
	flags.BoolVar(&listSupportedServices, "list-supported-services", false, "do not detect; only print supported services")

	return cmd
}
