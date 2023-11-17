package hubtest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type NucleiConfig struct {
	Path           string   `yaml:"nuclei_path"`
	OutputDir      string   `yaml:"output_dir"`
	CmdLineOptions []string `yaml:"cmdline_options"`
}

var NucleiTemplateFail = errors.New("Nuclei template failed")

func (ts *NucleiConfig) RunNucleiTemplate(test_name string, template_path string, target string) error {
	tstamp := time.Now().Unix()
	//template_path is the full path to the template, we just want the name ie. "sqli-random-test"
	tmp := strings.Split(template_path, "/")
	template := strings.Split(tmp[len(tmp)-1], ".")[0]

	output_prefix := fmt.Sprintf("%s/%s_%s-%d", ts.OutputDir, test_name, template, tstamp)

	args := []string{
		"-u", target,
		"-t", template_path,
		"-o", output_prefix + ".json",
	}
	args = append(args, ts.CmdLineOptions...)
	cmd := exec.Command(ts.Path, args...)

	var out bytes.Buffer
	var out_err bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out_err
	err := cmd.Run()
	if err := os.WriteFile(output_prefix+"_stdout.txt", out.Bytes(), 0644); err != nil {
		log.Warningf("Error writing stdout: %s", err)
	}
	if err := os.WriteFile(output_prefix+"_stderr.txt", out_err.Bytes(), 0644); err != nil {
		log.Warningf("Error writing stderr: %s", err)
	}
	if err != nil {
		log.Warningf("Error running nuclei: %s", err)
		log.Warningf("Stdout saved to %s", output_prefix+"_stdout.txt")
		log.Warningf("Stderr saved to %s", output_prefix+"_stderr.txt")
		log.Warningf("Nuclei generated output saved to %s", output_prefix+".json")
		return err
	} else if len(out.String()) == 0 {
		//No stdout means no finding, it means our test failed
		return NucleiTemplateFail
	}
	return nil
}
