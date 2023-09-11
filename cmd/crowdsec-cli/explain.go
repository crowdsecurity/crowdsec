package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/hubtest"
)

func GetLineCountForFile(filepath string) (int, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	lc := 0
	fs := bufio.NewScanner(f)
	for fs.Scan() {
		lc++
	}
	return lc, nil
}

func runExplain(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	logFile, err := flags.GetString("file")
	if err != nil {
		return err
	}

	dsn, err := flags.GetString("dsn")
	if err != nil {
		return err
	}

	logLine, err := flags.GetString("log")
	if err != nil {
		return err
	}

	logType, err := flags.GetString("type")
	if err != nil {
		return err
	}

	opts := hubtest.DumpOpts{}

	opts.Details, err = flags.GetBool("verbose")
	if err != nil {
		return err
	}

	opts.SkipOk, err = flags.GetBool("failures")
	if err != nil {
		return err
	}

	opts.ShowNotOkParsers, err = flags.GetBool("only-successful-parsers")
	opts.ShowNotOkParsers = !opts.ShowNotOkParsers
	if err != nil {
		return err
	}

	crowdsec, err := flags.GetString("crowdsec")
	if err != nil {
		return err
	}

	labels, err := flags.GetString("labels")
	if err != nil {
		return err
	}

	fileInfo, _ := os.Stdin.Stat()

	if logType == "" || (logLine == "" && logFile == "" && dsn == "") {
		printHelp(cmd)
		fmt.Println()
		fmt.Printf("Please provide --type flag\n")
		os.Exit(1)
	}

	if logFile == "-" && ((fileInfo.Mode() & os.ModeCharDevice) == os.ModeCharDevice) {
		return fmt.Errorf("the option -f - is intended to work with pipes")
	}

	var f *os.File

	// using empty string fallback to /tmp
	dir, err := os.MkdirTemp("", "cscli_explain")
	if err != nil {
		return fmt.Errorf("couldn't create a temporary directory to store cscli explain result: %s", err)
	}
	tmpFile := ""
	// we create a  temporary log file if a log line/stdin has been provided
	if logLine != "" || logFile == "-" {
		tmpFile = filepath.Join(dir, "cscli_test_tmp.log")
		f, err = os.Create(tmpFile)
		if err != nil {
			return err
		}

		if logLine != "" {
			_, err = f.WriteString(logLine)
			if err != nil {
				return err
			}
		} else if logFile == "-" {
			reader := bufio.NewReader(os.Stdin)
			errCount := 0
			for {
				input, err := reader.ReadBytes('\n')
				if err != nil && err == io.EOF {
					break
				}
				_, err = f.Write(input)
				if err != nil {
					errCount++
				}
			}
			if errCount > 0 {
				log.Warnf("Failed to write %d lines to tmp file", errCount)
			}
		}
		f.Close()
		// this is the file that was going to be read by crowdsec anyway
		logFile = tmpFile
	}

	if logFile != "" {
		absolutePath, err := filepath.Abs(logFile)
		if err != nil {
			return fmt.Errorf("unable to get absolute path of '%s', exiting", logFile)
		}
		dsn = fmt.Sprintf("file://%s", absolutePath)
		lineCount, err := GetLineCountForFile(absolutePath)
		if err != nil {
			return err
		}
		if lineCount > 100 {
			log.Warnf("log file contains %d lines. This may take lot of resources.", lineCount)
		}
	}

	if dsn == "" {
		return fmt.Errorf("no acquisition (--file or --dsn) provided, can't run cscli test")
	}

	cmdArgs := []string{"-c", ConfigFilePath, "-type", logType, "-dsn", dsn, "-dump-data", dir, "-no-api"}
	if labels != "" {
		log.Debugf("adding labels %s", labels)
		cmdArgs = append(cmdArgs, "-label", labels)
	}
	crowdsecCmd := exec.Command(crowdsec, cmdArgs...)
	output, err := crowdsecCmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(output))
		return fmt.Errorf("fail to run crowdsec for test: %v", err)
	}

	// rm the temporary log file if only a log line/stdin was provided
	if tmpFile != "" {
		if err := os.Remove(tmpFile); err != nil {
			return fmt.Errorf("unable to remove tmp log file '%s': %+v", tmpFile, err)
		}
	}
	parserDumpFile := filepath.Join(dir, hubtest.ParserResultFileName)
	bucketStateDumpFile := filepath.Join(dir, hubtest.BucketPourResultFileName)

	parserDump, err := hubtest.LoadParserDump(parserDumpFile)
	if err != nil {
		return fmt.Errorf("unable to load parser dump result: %s", err)
	}

	bucketStateDump, err := hubtest.LoadBucketPourDump(bucketStateDumpFile)
	if err != nil {
		return fmt.Errorf("unable to load bucket dump result: %s", err)
	}

	hubtest.DumpTree(*parserDump, *bucketStateDump, opts)

	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("unable to delete temporary directory '%s': %s", dir, err)
	}

	return nil
}

func NewExplainCmd() *cobra.Command {
	cmdExplain := &cobra.Command{
		Use:   "explain",
		Short: "Explain log pipeline",
		Long: `
Explain log pipeline 
		`,
		Example: `
cscli explain --file ./myfile.log --type nginx 
cscli explain --log "Sep 19 18:33:22 scw-d95986 sshd[24347]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4" --type syslog
cscli explain --dsn "file://myfile.log" --type nginx
tail -n 5 myfile.log | cscli explain --type nginx -f -
		`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE:              runExplain,
	}

	flags := cmdExplain.Flags()

	flags.StringP("file", "f", "", "Log file to test")
	flags.StringP("dsn", "d", "", "DSN to test")
	flags.StringP("log", "l", "", "Log line to test")
	flags.StringP("type", "t", "", "Type of the acquisition to test")
	flags.String("labels", "", "Additional labels to add to the acquisition format (key:value,key2:value2)")
	flags.BoolP("verbose", "v", false, "Display individual changes")
	flags.Bool("failures", false, "Only show failed lines")
	flags.Bool("only-successful-parsers", false, "Only show successful parsers")
	flags.String("crowdsec", "crowdsec", "Path to crowdsec")

	return cmdExplain
}
