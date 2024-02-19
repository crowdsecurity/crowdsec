package hubtest

import (
	"bytes"
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

var ErrNucleiTemplateFail = errors.New("nuclei template failed")

func (nc *NucleiConfig) RunNucleiTemplate(testName string, templatePath string, target string) error {
	tstamp := time.Now().Unix()

	outputPrefix := fmt.Sprintf("%s/%s-%d", nc.OutputDir, testName, tstamp)
	// CVE-2023-34362_CVE-2023-34362-1702562399_stderr.txt
	args := []string{
		"-u", target,
		"-t", templatePath,
		"-o", outputPrefix + ".json",
	}
	args = append(args, nc.CmdLineOptions...)
	cmd := exec.Command(nc.Path, args...)

	log.Debugf("Running Nuclei command: '%s'", cmd.String())

	var out bytes.Buffer
	var outErr bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &outErr

	err := cmd.Run()

	if err := os.WriteFile(outputPrefix+"_stdout.txt", out.Bytes(), 0644); err != nil {
		log.Warningf("Error writing stdout: %s", err)
	}

	if err := os.WriteFile(outputPrefix+"_stderr.txt", outErr.Bytes(), 0644); err != nil {
		log.Warningf("Error writing stderr: %s", err)
	}

	if err != nil {
		log.Warningf("Error running nuclei: %s", err)
		log.Warningf("Stdout saved to %s", outputPrefix+"_stdout.txt")
		log.Warningf("Stderr saved to %s", outputPrefix+"_stderr.txt")
		log.Warningf("Nuclei generated output saved to %s", outputPrefix+".json")
		return err
	} else if len(out.String()) == 0 {
		log.Warningf("Stdout saved to %s", outputPrefix+"_stdout.txt")
		log.Warningf("Stderr saved to %s", outputPrefix+"_stderr.txt")
		log.Warningf("Nuclei generated output saved to %s", outputPrefix+".json")
		//No stdout means no finding, it means our test failed
		return ErrNucleiTemplateFail
	}
	return nil
}
