package main

import (
	"bufio"
	"errors"
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
	fs := bufio.NewReader(f)
	for {
		input, err := fs.ReadBytes('\n')
		if len(input) > 1 {
			lc++
		}
		if err != nil && err == io.EOF {
			break
		}
	}
	return lc, nil
}

type cliExplain struct {}

func NewCLIExplain() *cliExplain {
	return &cliExplain{}
}

func (cli cliExplain) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
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
		RunE:              cli.run,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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

			if logLine == "" && logFile == "" && dsn == "" {
				printHelp(cmd)
				fmt.Println()
				return fmt.Errorf("please provide --log, --file or --dsn flag")
			}
			if logType == "" {
				printHelp(cmd)
				fmt.Println()
				return fmt.Errorf("please provide --type flag")
			}
			fileInfo, _ := os.Stdin.Stat()
			if logFile == "-" && ((fileInfo.Mode() & os.ModeCharDevice) == os.ModeCharDevice) {
				return fmt.Errorf("the option -f - is intended to work with pipes")
			}
			return nil
		},
	}

	flags := cmd.Flags()

	flags.StringP("file", "f", "", "Log file to test")
	flags.StringP("dsn", "d", "", "DSN to test")
	flags.StringP("log", "l", "", "Log line to test")
	flags.StringP("type", "t", "", "Type of the acquisition to test")
	flags.String("labels", "", "Additional labels to add to the acquisition format (key:value,key2:value2)")
	flags.BoolP("verbose", "v", false, "Display individual changes")
	flags.Bool("failures", false, "Only show failed lines")
	flags.Bool("only-successful-parsers", false, "Only show successful parsers")
	flags.String("crowdsec", "crowdsec", "Path to crowdsec")

	return cmd
}

func (cli cliExplain) run(cmd *cobra.Command, args []string) error {
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

	var f *os.File

	// using empty string fallback to /tmp
	dir, err := os.MkdirTemp("", "cscli_explain")
	if err != nil {
		return fmt.Errorf("couldn't create a temporary directory to store cscli explain result: %s", err)
	}
	defer func() {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			if err := os.RemoveAll(dir); err != nil {
				log.Errorf("unable to delete temporary directory '%s': %s", dir, err)
			}
		}
	}()
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
				if err != nil && errors.Is(err, io.EOF) {
					break
				}
				if len(input) > 1 {
					_, err = f.Write(input)
				}
				if err != nil || len(input) <= 1 {
					errCount++
				}
			}
			if errCount > 0 {
				log.Warnf("Failed to write %d lines to %s", errCount, tmpFile)
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
		log.Debugf("file %s has %d lines", absolutePath, lineCount)
		if lineCount == 0 {
			return fmt.Errorf("the log file is empty: %s", absolutePath)
		}
		if lineCount > 100 {
			log.Warnf("%s contains %d lines. This may take a lot of resources.", absolutePath, lineCount)
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

	return nil
}
