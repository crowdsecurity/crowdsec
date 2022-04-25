package bincover

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
)

const (
	set                          = "set"
	count                        = "count"
	atomic                       = "atomic"
	defaultTmpArgsFilePrefix     = "integ_args"
	defaultTmpCoverageFilePrefix = "temp_coverage"
)

type CoverageCollector struct {
	MergedCoverageFilename string
	CollectCoverage        bool
	tmpArgsFile            *os.File
	coverMode              string
	tmpCoverageFiles       []*os.File
	setupFinished          bool
	preCmdFuncs            []PreCmdFunc
	postCmdFuncs           []PostCmdFunc
}
type CoverageCollectorOption func(collector *CoverageCollector)
type PreCmdFunc func(cmd *exec.Cmd) error
type PostCmdFunc func(cmd *exec.Cmd, output string, err error) error

// NewCoverageCollector initializes a CoverageCollector with the specified
// merged coverage filename. CollectCoverage can be set to true to collect coverage,
// or set to false to skip coverage collection. This is provided in order to enable reuse of CoverageCollector
// for tests where coverage measurement is not needed.
func NewCoverageCollector(mergedCoverageFilename string, collectCoverage bool) *CoverageCollector {
	return &CoverageCollector{
		MergedCoverageFilename: mergedCoverageFilename,
		CollectCoverage:        collectCoverage,
	}
}

func (c *CoverageCollector) Setup() error {
	if c.MergedCoverageFilename == "" && c.CollectCoverage {
		return errors.New("merged coverage profile filename cannot be empty when CollectCoverage is true")
	}
	var err error
	c.tmpArgsFile, err = ioutil.TempFile("", defaultTmpArgsFilePrefix)
	if err != nil {
		return errors.Wrap(err, "error creating temporary args file")
	}
	c.setupFinished = true
	return nil
}

// TearDown merges the coverage profiles collecting from repeated runs of RunBinary.
// It must be called at the teardown stage of the test suite, otherwise no merged coverage profile will be created.
func (c *CoverageCollector) TearDown() error {
	if len(c.tmpCoverageFiles) == 0 {
		return nil
	}
	defer c.removeTempFiles()
	header := fmt.Sprintf("mode: %s", c.coverMode)
	var parsedProfiles []string
	for _, file := range c.tmpCoverageFiles {
		buf, err := ioutil.ReadAll(file)
		if err != nil {
			return errors.Wrap(err, "error reading temp coverage profiles")
		}
		profile := string(buf)
		loc := strings.Index(profile, header)
		if loc == -1 {
			errMessage := "error parsing coverage profile: missing coverage mode from coverage profile. Maybe the file got corrupted while writing?"
			return errors.New(errMessage)
		}
		parsedProfile := strings.TrimSpace(profile[loc+len(header):])
		parsedProfiles = append(parsedProfiles, parsedProfile)
	}
	mergedProfile := fmt.Sprintf("%s\n%s", header, strings.Join(parsedProfiles, "\n"))
	err := ioutil.WriteFile(c.MergedCoverageFilename, []byte(mergedProfile), 0600)
	if err != nil {
		return errors.Wrap(err, "error writing merged coverage profile")
	}
	return nil
}

func PreExec(preCmdFuncs ...PreCmdFunc) CoverageCollectorOption {
	return func(c *CoverageCollector) {
		c.preCmdFuncs = preCmdFuncs
	}
}

func PostExec(postCmdFuncs ...PostCmdFunc) CoverageCollectorOption {
	return func(c *CoverageCollector) {
		c.postCmdFuncs = postCmdFuncs
	}
}

// RunBinary runs the instrumented binary at binPath with env environment variables, executing only the test with mainTestName with the specified args.
func (c *CoverageCollector) RunBinary(binPath string, mainTestName string, env []string, args []string, options ...CoverageCollectorOption) (output string, exitCode int, err error) {
	if !c.setupFinished {
		panic("RunBinary called before Setup")
	}
	err = c.writeArgs(args)
	if err != nil {
		return "", -1, err
	}
	for _, option := range options {
		option(c)
	}
	var binArgs string
	var tempCovFile *os.File
	if c.CollectCoverage {
		tempCovFile, err = ioutil.TempFile("", defaultTmpCoverageFilePrefix)
		if err != nil {
			return "", -1, err
		}
		binArgs = fmt.Sprintf("-test.run=^%s$ -test.coverprofile=%s -args-file=%s", mainTestName, tempCovFile.Name(), c.tmpArgsFile.Name())
	} else {
		binArgs = fmt.Sprintf("-test.run=^%s$ -args-file=%s", mainTestName, c.tmpArgsFile.Name())
	}
	cmd := exec.Command(binPath, strings.Split(binArgs, " ")...)
	cmd.Env = append(os.Environ(), env...)
	for _, cmdFunc := range c.preCmdFuncs {
		if err := cmdFunc(cmd); err != nil {
			return "", -1, err
		}
	}
	combinedOutput, err := cmd.CombinedOutput()
	binOutput := string(combinedOutput)
	if err != nil {
		if tempCovFile != nil {
			removeTempCoverageFile(tempCovFile.Name())
		}
		// This exit code testing requires 1.12 - https://stackoverflow.com/a/55055100/337735.
		if exitError, ok := err.(*exec.ExitError); ok {
			binExitCode := exitError.ExitCode()
			format := "unsuccessful exit by command \"%s\"\nExit code: %d\nOutput:\n%s"
			return "", binExitCode, errors.Wrapf(exitError, format, binPath, binExitCode, binOutput)

		} else {
			format := "unexpected error running command \"%s\""
			return "", -1, errors.Wrapf(err, format, binPath)
		}
	}
	haveTestsToRun := haveTestsToRun(binOutput)
	if !haveTestsToRun {
		return "", -1, errors.New(binOutput)
	}
	if tempCovFile != nil {
		c.tmpCoverageFiles = append(c.tmpCoverageFiles, tempCovFile)
	}
	cmdOutput, coverMode, exitCode := parseCommandOutput(string(combinedOutput))
	for _, cmdFunc := range c.postCmdFuncs {
		if e := cmdFunc(cmd, cmdOutput, err); e != nil {
			return "", -1, e
		}
	}
	if c.CollectCoverage {
		if c.coverMode == "" {
			c.coverMode = coverMode
		}
		if c.coverMode == "" {
			panic("coverage mode cannot be empty. test coverage must be enabled when CollectCoverage is set to true")
		}
		// https://github.com/wadey/gocovmerge/blob/b5bfa59ec0adc420475f97f89b58045c721d761c/gocovmerge.go#L18
		if c.coverMode != coverMode {
			panic("cannot merge profiles with different coverage modes")
		}
		if c.coverMode != set && c.coverMode != count && c.coverMode != atomic {
			log.Panicf("unexpected coverage mode \"%s\" encountered. Coverage mode must be set, count, or atomic", c.coverMode)
		}
	}
	return cmdOutput, exitCode, err
}

func (c *CoverageCollector) writeArgs(args []string) error {
	err := c.tmpArgsFile.Truncate(0)
	if err != nil {
		return err
	}
	_, err = c.tmpArgsFile.Seek(0, 0)
	if err != nil {
		return err
	}
	argStr := strings.Join(args, "\n")
	_, err = c.tmpArgsFile.WriteAt([]byte(argStr), 0)
	if err != nil {
		return err
	}
	return err
}

func parseCommandOutput(output string) (cmdOutput string, coverMode string, exitCode int) {
	startIndex := strings.Index(output, startOfMetadataMarker)
	if startIndex == -1 {
		panic("metadata start marker is unexpectedly missing")
	}
	endIndex := strings.Index(output, endOfMetadataMarker)
	if endIndex == -1 {
		panic("metadata end marker is unexpectedly missing")
	}
	cmdOutput = output[:startIndex]
	tail := output[startIndex+len(startOfMetadataMarker) : endIndex]
	// Trim extra newline after cmd output.
	metadataStr := strings.TrimSpace(tail)
	var metadata testMetadata
	err := json.Unmarshal([]byte(metadataStr), &metadata)
	if err != nil {
		panic("error unmarshalling testMetadata struct from RunTest")
	}
	return cmdOutput, metadata.CoverMode, metadata.ExitCode
}

func (c *CoverageCollector) removeTempFiles() {
	for _, file := range c.tmpCoverageFiles {
		removeTempCoverageFile(file.Name())
	}
	if c.tmpArgsFile != nil {
		err := os.Remove(c.tmpArgsFile.Name())
		if err != nil {
			log.Printf("error removing temp arg file: %s\n", err)
		}
	}
}

func removeTempCoverageFile(name string) {
	err := os.Remove(name)
	if err != nil {
		log.Printf("error removing temp coverage file: %s\n", err)
	}
}

func haveTestsToRun(output string) bool {
	prefix := "testing: warning: no tests to run"
	return !strings.HasPrefix(output, prefix)
}
