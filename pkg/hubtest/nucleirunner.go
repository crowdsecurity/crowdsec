package hubtest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	log "github.com/sirupsen/logrus"
)

type NucleiConfig struct {
	Path           string   `yaml:"nuclei_path"`
	OutputDir      string   `yaml:"output_dir"`
	CmdLineOptions []string `yaml:"cmdline_options"`
}

var (
	ErrNucleiTemplateFail = errors.New("nuclei template failed")
	ErrNucleiRunFail = errors.New("nuclei run failed")
)

func (nc *NucleiConfig) RunNucleiTemplate(ctx context.Context, testName string, templatePath string, target string) error {
	tstamp := time.Now().Unix()

	outputPrefix := fmt.Sprintf("%s/%s-%d", nc.OutputDir, testName, tstamp)
	// CVE-2023-34362_CVE-2023-34362-1702562399_stderr.txt
	args := []string{
		// removing the banner with --silent also removes useful [WRN] lines, so it is what it is
		// "-silent",
		"-u", target,
		"-t", templatePath,
		"-o", outputPrefix + ".json",
	}
	args = append(args, nc.CmdLineOptions...)
	cmd := exec.CommandContext(ctx, nc.Path, args...)

	log.Debugf("Running Nuclei command: '%s'", cmd.String())

	var (
		out bytes.Buffer
		outErr bytes.Buffer
	)

	cmd.Stdout = &out
	cmd.Stderr = &outErr

	cmdErr := cmd.Run()
	if err := os.WriteFile(outputPrefix+"_stdout.txt", out.Bytes(), 0o644); err != nil {
		log.Errorf("Error writing stdout: %s", err)
	}

	errBytes := outErr.Bytes()

	if err := os.WriteFile(outputPrefix+"_stderr.txt", errBytes, 0o644); err != nil {
		log.Errorf("Error writing stderr: %s", err)
	}

	if cmdErr != nil {
		// display stderr in addition to writing to a file
		os.Stdout.Write(errBytes)
		os.Stdout.WriteString("\n")

		fmt.Fprintln(os.Stdout, "Stdout saved to", outputPrefix+"_stdout.txt")
		fmt.Fprintln(os.Stdout, "Stderr saved to", outputPrefix+"_stderr.txt")
		fmt.Fprintln(os.Stdout, "Nuclei generated output saved to", outputPrefix+".json")

		return fmt.Errorf("%w: %v", ErrNucleiRunFail, cmdErr)
	}

	if out.String() == "" {
		fmt.Fprintln(os.Stdout, "Stdout saved to", outputPrefix+"_stdout.txt")
		fmt.Fprintln(os.Stdout, "Stderr saved to", outputPrefix+"_stderr.txt")
		fmt.Fprintln(os.Stdout, "Nuclei generated output saved to", outputPrefix+".json")

		// No stdout means no finding, it means our test failed
		return ErrNucleiTemplateFail
	}

	return nil
}
