package clisetup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"

	goccyyaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

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
	installHub            bool
	datasources           bool
	interactive           bool
	dryRun                bool
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
	flags.StringVar(&f.forcedOSID, "force-os-id", "", "override OS.ID=[debian | ubuntu | redhat...]")
	flags.StringVar(&f.forcedOSVersion, "force-os-version", "", "override OS.RawVersion (of OS or Linux distribution)")
	flags.BoolVar(&f.snubSystemd, "snub-systemd", false, "don't use systemd, even if available")
	flags.BoolVar(&f.outYaml, "yaml", false, "output yaml, not json")
	flags.BoolVar(&f.installHub, "install-hub", false, "install detected collections")
	flags.BoolVar(&f.datasources, "datasources", false, "install detected log sources")
	flags.BoolVarP(&f.interactive, "interactive", "i", false, "Ask for confirmation before proceeding (with --install-hub)")
	flags.BoolVar(&f.dryRun, "dry-run", false, "don't install anything; print out what would have been (with --install-hub)")
	// XXX TODO: mutually exclusive options, etc.

	flags.SortFlags = false
}

func (cli *cliSetup) newDetectCmd() *cobra.Command {
	f := detectFlags{}

	cmd := &cobra.Command{
		Use:               "detect",
		Short:             "detect running services, generate a setup file",
		Args:              args.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.detect(cmd.Context(), f)
		},
	}

	f.bind(cmd)

	return cmd
}

func (cli *cliSetup) detect(ctx context.Context, f detectFlags) error {
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
		_, err = exec.LookPath("systemctl")
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

	if f.installHub {
		if err := cli.install(ctx, f.interactive, f.dryRun, bytes.NewBufferString(setup)); err != nil {
			return err
		}
	}

	if f.datasources {
		acquisDir := cli.cfg().Crowdsec.AcquisitionDirPath
		if err := cli.dataSources(bytes.NewBufferString(setup), acquisDir); err != nil {
			return err
		}
	}

	if !f.installHub && !f.datasources {
		fmt.Println(setup)
	}


	return nil
}

func setupAsString(cs setup.Setup, outYaml bool) (string, error) {
	var (
		ret []byte
		err error
	)

	wrap := func(err error) error {
		return fmt.Errorf("while serializing setup: %w", err)
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
