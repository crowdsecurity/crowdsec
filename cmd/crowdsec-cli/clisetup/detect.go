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
	detectConfigFile      string
	forcedUnits           []string
	forcedProcesses       []string
	forcedOSFamily        string
	forcedOSID            string
	forcedOSVersion       string
	skipServices          []string
	snubSystemd           bool
}

func (f *detectFlags) bind(cmd *cobra.Command) {
	defaultServiceDetect := csconfig.DefaultConfigPath("detect.yaml")

	flags := cmd.Flags()
	flags.StringVar(&f.detectConfigFile, "detect-config", defaultServiceDetect, "path to service detection configuration")
	flags.StringSliceVar(&f.forcedUnits, "force-unit", nil, "force detection of a systemd unit (can be repeated)")
	flags.StringSliceVar(&f.forcedProcesses, "force-process", nil, "force detection of a running process (can be repeated)")
	flags.StringSliceVar(&f.skipServices, "skip-service", nil, "ignore a service, don't recommend hub/datasources (can be repeated)")
	flags.StringVar(&f.forcedOSFamily, "force-os-family", "", "override OS.Family: one of linux, freebsd, windows or darwin")
	flags.StringVar(&f.forcedOSID, "force-os-id", "", "override OS.ID=[debian | ubuntu | redhat...]")
	flags.StringVar(&f.forcedOSVersion, "force-os-version", "", "override OS.RawVersion (of OS or Linux distribution)")
	flags.BoolVar(&f.snubSystemd, "snub-systemd", false, "don't use systemd, even if available")

	flags.SortFlags = false
}

func (f *detectFlags) toDetectOptions(logger *logrus.Logger) setup.DetectOptions {
	if !f.snubSystemd {
		if _, err := exec.LookPath("systemctl"); err != nil {
			logger.Debug("systemctl not available: snubbing systemd")

			f.snubSystemd = true
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
		SnubSystemd:  f.snubSystemd,
	}
}

func (cli *cliSetup) newDetectCmd() *cobra.Command {
	f := detectFlags{}
	var (
		outYaml bool
		listSupportedServices bool
	)

	cmd := &cobra.Command{
		Use:               "detect",
		Short:             "detect running services, generate a setup file",
		Args:              args.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			detectReader, err := maybeStdinFile(f.detectConfigFile)
			if err != nil {
				return err
			}

			rulesFrom := f.detectConfigFile

			if detectReader == os.Stdin {
				rulesFrom = "<stdin>"
			}

			detector, err := setup.NewDetector(detectReader)
			if err != nil {
				return fmt.Errorf("parsing %s: %w", rulesFrom, err)
			}

			if listSupportedServices {
				for _, svc := range detector.ListSupportedServices() {
					fmt.Println(svc)
				}

				return nil
			}

			logger := logrus.StandardLogger()

			stup, err := setup.NewSetup(detector, f.toDetectOptions(logger), logger)
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
