package cliexplain

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

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/dumps"
	"github.com/crowdsecurity/crowdsec/pkg/hubtest"
)

func getLineCountForFile(filepath string) (int, error) {
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

type configGetter func() *csconfig.Config

type cliExplain struct {
	cfg            configGetter
	configFilePath string
	flags          struct {
		logFile               string
		dsn                   string
		logLine               string
		logType               string
		details               bool
		skipOk                bool
		onlySuccessfulParsers bool
		noClean               bool
		crowdsec              string
		labels                string
	}
}

func New(cfg configGetter, configFilePath string) *cliExplain {
	return &cliExplain{
		cfg:            cfg,
		configFilePath: configFilePath,
	}
}

func (cli *cliExplain) NewCommand() *cobra.Command {
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
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.run()
		},
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			fileInfo, _ := os.Stdin.Stat()
			if cli.flags.logFile == "-" && ((fileInfo.Mode() & os.ModeCharDevice) == os.ModeCharDevice) {
				return errors.New("the option -f - is intended to work with pipes")
			}

			return nil
		},
	}

	flags := cmd.Flags()

	flags.StringVarP(&cli.flags.logFile, "file", "f", "", "Log file to test")
	flags.StringVarP(&cli.flags.dsn, "dsn", "d", "", "DSN to test")
	flags.StringVarP(&cli.flags.logLine, "log", "l", "", "Log line to test")
	flags.StringVarP(&cli.flags.logType, "type", "t", "", "Type of the acquisition to test")
	flags.StringVar(&cli.flags.labels, "labels", "", "Additional labels to add to the acquisition format (key:value,key2:value2)")
	flags.BoolVarP(&cli.flags.details, "verbose", "v", false, "Display individual changes")
	flags.BoolVar(&cli.flags.skipOk, "failures", false, "Only show failed lines")
	flags.BoolVar(&cli.flags.onlySuccessfulParsers, "only-successful-parsers", false, "Only show successful parsers")
	flags.StringVar(&cli.flags.crowdsec, "crowdsec", "crowdsec", "Path to crowdsec")
	flags.BoolVar(&cli.flags.noClean, "no-clean", false, "Don't clean runtime environment after tests")

	_ = cmd.MarkFlagRequired("type")
	cmd.MarkFlagsOneRequired("log", "file", "dsn")

	return cmd
}

func (cli *cliExplain) run() error {
	logFile := cli.flags.logFile
	logLine := cli.flags.logLine
	logType := cli.flags.logType
	dsn := cli.flags.dsn
	labels := cli.flags.labels
	crowdsec := cli.flags.crowdsec

	opts := dumps.DumpOpts{
		Details:          cli.flags.details,
		SkipOk:           cli.flags.skipOk,
		ShowNotOkParsers: !cli.flags.onlySuccessfulParsers,
	}

	var f *os.File

	// using empty string fallback to /tmp
	dir, err := os.MkdirTemp("", "cscli_explain")
	if err != nil {
		return fmt.Errorf("couldn't create a temporary directory to store cscli explain result: %w", err)
	}

	defer func() {
		if cli.flags.noClean {
			return
		}

		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			if err := os.RemoveAll(dir); err != nil {
				log.Errorf("unable to delete temporary directory '%s': %s", dir, err)
			}
		}
	}()

	// we create a  temporary log file if a log line/stdin has been provided
	if logLine != "" || logFile == "-" {
		tmpFile := filepath.Join(dir, "cscli_test_tmp.log")

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

		dsn = "file://" + absolutePath

		lineCount, err := getLineCountForFile(absolutePath)
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
		return errors.New("no acquisition (--file or --dsn) provided, can't run cscli test")
	}

	cmdArgs := []string{"-c", cli.configFilePath, "-type", logType, "-dsn", dsn, "-dump-data", dir, "-no-api"}

	if labels != "" {
		log.Debugf("adding labels %s", labels)
		cmdArgs = append(cmdArgs, "-label", labels)
	}

	crowdsecCmd := exec.Command(crowdsec, cmdArgs...)

	output, err := crowdsecCmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(output))

		return fmt.Errorf("fail to run crowdsec for test: %w", err)
	}

	parserDumpFile := filepath.Join(dir, hubtest.ParserResultFileName)
	bucketStateDumpFile := filepath.Join(dir, hubtest.BucketPourResultFileName)

	parserDump, err := dumps.LoadParserDump(parserDumpFile)
	if err != nil {
		return fmt.Errorf("unable to load parser dump result: %w", err)
	}

	bucketStateDump, err := dumps.LoadBucketPourDump(bucketStateDumpFile)
	if err != nil {
		return fmt.Errorf("unable to load bucket dump result: %w", err)
	}

	dumps.DumpTree(*parserDump, *bucketStateDump, opts)

	return nil
}
