package clisetup

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clisetup/setup"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/args"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

// detectFlags are reused for "unattended" and "interactive"
type detectFlags struct {
	detectConfigFile string
	skipServices     []string
	wantServices     []string
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
		defaultServiceDetect = csconfig.DefaultDataPath("detect.yaml")
	}

	flags := cmd.Flags()
	flags.StringVar(&f.detectConfigFile, "detect-config", defaultServiceDetect, "path to service detection configuration, will use $CROWDSEC_SETUP_DETECT_CONFIG if defined")
	flags.StringSliceVar(&f.skipServices, "ignore", nil, "ignore a detected service (can be repeated)")
	flags.StringSliceVar(&f.wantServices, "force", nil, "force the detection of a service (can be repeated)")
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

	logger.Debug("SkipServices: ", f.skipServices)
	logger.Debug("WantServices: ", f.wantServices)
	logger.Debug("SkipSystemd: ", f.skipSystemd)

	return setup.DetectOptions{
		SkipServices: f.skipServices,
		WantServices: f.wantServices,
		SkipSystemd:  f.skipSystemd,
	}
}

func (*cliSetup) newDetectCmd() *cobra.Command {
	f := detectFlags{}

	var (
		outYaml               bool
		listSupportedServices bool
	)

	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Detect installed services and generate a setup file",
		Long: `Detects the services installed on the machine and builds a specification
to be used with the "setup install-*" commands.`,
		Example: `# detect services and print the setup plan
cscli setup detect

# force yaml instead of json (easier to edit)
cscli setup detect --yaml

# detect and skip certain services
cscli setup detect --ignore whitelists
`,
		Args:              args.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
				if units, err = setup.DetectSystemdUnits(ctx, exec.CommandContext); err != nil {
					return err
				}
			}

			procs, err := setup.DetectProcesses(ctx, logger)
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
