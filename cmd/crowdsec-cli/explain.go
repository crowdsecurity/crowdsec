package main

import (
	"fmt"
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
		`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {

			if logType == "" || (logLine == "" && logFile == "" && dsn == "") {
				printHelp(cmd)
				fmt.Println()
				fmt.Printf("Please provide --type flag\n")
				os.Exit(1)
			}

			// we create a temporary log file if a log line has been provided
			if logLine != "" {
				logFile = "./cscli_test_tmp.log"
				f, err := os.Create(logFile)
				if err != nil {
					log.Fatal(err)
				}
				defer f.Close()

				_, err = f.WriteString(logLine)
				if err != nil {
					log.Fatal(err)
				}
			}

			if logFile != "" {
				absolutePath, err := filepath.Abs(logFile)
				if err != nil {
					log.Fatalf("unable to get absolue path of '%s', exiting", logFile)
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
			output, err := crowdsecCmd.CombinedOutput()
			if err != nil {
				fmt.Println(string(output))
				log.Fatalf("fail to run crowdsec for test: %v", err)
			}

			// rm the temporary log file if only a log line was provided
			if logLine != "" {
				if err := os.Remove(logFile); err != nil {
					log.Fatalf("unable to remove tmp log file '%s': %+v", logFile, err)
				}
			}
			parserDumpFile := filepath.Join("./", cstest.ParserResultFileName)
			bucketStateDumpFile := filepath.Join("./", cstest.BucketPourResultFileName)

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
