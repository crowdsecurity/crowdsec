package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewExplainCmd() *cobra.Command {
	/* ---- HUB COMMAND */
	var logFile string
	var dsn string
	var logLine string
	var logType string
	var opts cstest.DumpOpts
	var err error

	var cmdExplain = &cobra.Command{
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
		Run: func(cmd *cobra.Command, args []string) {
			fileInfo, _ := os.Stdin.Stat()

			if logType == "" || (logLine == "" && logFile == "" && dsn == "") {
				printHelp(cmd)
				fmt.Println()
				fmt.Printf("Please provide --type flag\n")
				os.Exit(1)
			}

			if logFile == "-" && ((fileInfo.Mode() & os.ModeCharDevice) == os.ModeCharDevice) {
				log.Fatal("-f - is intended to work with pipes.")
			}

			var f *os.File
			dir := os.TempDir()

			tmpFile := ""
			// we create a  temporary log file if a log line/stdin has been provided
			if logLine != "" || logFile == "-" {
				tmpFile = filepath.Join(dir, "cscli_test_tmp.log")
				f, err = os.Create(tmpFile)
				if err != nil {
					log.Fatal(err)
				}

				if logLine != "" {
					_, err = f.WriteString(logLine)
					if err != nil {
						log.Fatal(err)
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
				//this is the file that was going to be read by crowdsec anyway
				logFile = tmpFile
			}

			if logFile != "" {
				absolutePath, err := filepath.Abs(logFile)
				if err != nil {
					log.Fatalf("unable to get absolute path of '%s', exiting", logFile)
				}
				dsn = fmt.Sprintf("file://%s", absolutePath)
				lineCount := types.GetLineCountForFile(absolutePath)
				if lineCount > 100 {
					log.Warnf("log file contains %d lines. This may take lot of resources.", lineCount)
				}
			}

			if dsn == "" {
				log.Fatal("no acquisition (--file or --dsn) provided, can't run cscli test.")
			}

			cmdArgs := []string{"-c", ConfigFilePath, "-type", logType, "-dsn", dsn, "-dump-data", "./", "-no-api"}
			crowdsecCmd := exec.Command("crowdsec", cmdArgs...)
			crowdsecCmd.Dir = dir
			output, err := crowdsecCmd.CombinedOutput()
			if err != nil {
				fmt.Println(string(output))
				log.Fatalf("fail to run crowdsec for test: %v", err)
			}

			// rm the temporary log file if only a log line/stdin was provided
			if tmpFile != "" {
				f.Close()
				if err := os.Remove(tmpFile); err != nil {
					log.Fatalf("unable to remove tmp log file '%s': %+v", tmpFile, err)
				}
			}
			parserDumpFile := filepath.Join(dir, cstest.ParserResultFileName)
			bucketStateDumpFile := filepath.Join(dir, cstest.BucketPourResultFileName)

			parserDump, err := cstest.LoadParserDump(parserDumpFile)
			if err != nil {
				log.Fatalf("unable to load parser dump result: %s", err)
			}

			bucketStateDump, err := cstest.LoadBucketPourDump(bucketStateDumpFile)
			if err != nil {
				log.Fatalf("unable to load bucket dump result: %s", err)
			}

			cstest.DumpTree(*parserDump, *bucketStateDump, opts)
		},
	}
	cmdExplain.PersistentFlags().StringVarP(&logFile, "file", "f", "", "Log file to test")
	cmdExplain.PersistentFlags().StringVarP(&dsn, "dsn", "d", "", "DSN to test")
	cmdExplain.PersistentFlags().StringVarP(&logLine, "log", "l", "", "Log line to test")
	cmdExplain.PersistentFlags().StringVarP(&logType, "type", "t", "", "Type of the acquisition to test")
	cmdExplain.PersistentFlags().BoolVarP(&opts.Details, "verbose", "v", false, "Display individual changes")
	cmdExplain.PersistentFlags().BoolVar(&opts.SkipOk, "failures", false, "Only show failed lines")

	return cmdExplain
}
