package clisetup

import (
	"fmt"
	"os"
	"os/exec"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/setup"
)

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
	defaultServiceDetect := csconfig.DefaultConfigPath("detect.yaml")

	flags := cmd.Flags()
	flags.StringVar(&f.detectConfigFile, "detect-config", defaultServiceDetect, "path to service detection configuration")
	flags.BoolVar(&f.listSupportedServices, "list-supported-services", false, "do not detect; only print supported services")
	flags.StringSliceVar(&f.forcedUnits, "force-unit", nil, "force detection of a systemd unit (can be repeated)")
	flags.StringSliceVar(&f.forcedProcesses, "force-process", nil, "force detection of a running process (can be repeated)")
	flags.StringSliceVar(&f.skipServices, "skip-service", nil, "ignore a service, don't recommend hub/datasources (can be repeated)")
	flags.StringVar(&f.forcedOSFamily, "force-os-family", "", "override OS.Family: one of linux, freebsd, windows or darwin")
	flags.StringVar(&f.forcedOSID, "force-os-id", "", "override OS.ID=[debian | ubuntu | redhat...]")
	flags.StringVar(&f.forcedOSVersion, "force-os-version", "", "override OS.RawVersion (of OS or Linux distribution)")
	flags.BoolVar(&f.snubSystemd, "snub-systemd", false, "don't use systemd, even if available")
	flags.BoolVar(&f.outYaml, "yaml", false, "output yaml, not json")

	flags.SortFlags = false
}

func (f *detectFlags) detectOptions() setup.DetectOptions {
	if !f.snubSystemd {
		if _, err := exec.LookPath("systemctl"); err != nil {
			log.Debug("systemctl not available: snubbing systemd")

			f.snubSystemd = true
		}
	}

	if f.forcedOSFamily == "" && f.forcedOSID != "" {
		log.Debug("force-os-id is set: force-os-family defaults to 'linux'")

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

	cmd := &cobra.Command{
		Use:               "detect",
		Short:             "detect running services, generate a setup file",
		Args:              args.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				detectReader *os.File
				err error
			)

			rulesFrom := f.detectConfigFile

			switch f.detectConfigFile {
			case "-":
				rulesFrom = "<stdin>"
				detectReader = os.Stdin
			default:
				detectReader, err = os.Open(f.detectConfigFile)
				if err != nil {
					return err
				}
			}

			if f.listSupportedServices {
				supported, err := setup.ListSupported(detectReader)
				if err != nil {
					return fmt.Errorf("parsing %s: %w", rulesFrom, err)
				}

				for _, svc := range supported {
					fmt.Println(svc)
				}

				return nil
			}

			stup, err := setup.NewSetup(detectReader, f.detectOptions())
			if err != nil {
				return fmt.Errorf("parsing %s: %w", rulesFrom, err)
			}

			yamlBytes, err := stup.ToYAML(f.outYaml)
			if err != nil {
				return fmt.Errorf("while serializing setup: %w", err)
				
			}

			fmt.Fprintln(os.Stdout, string(yamlBytes))

			return nil
		},
	}

	f.bind(cmd)

	return cmd
}
