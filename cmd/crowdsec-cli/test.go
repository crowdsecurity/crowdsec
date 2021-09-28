package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func NewTestCmd() *cobra.Command {
	/* ---- HUB COMMAND */
	var logFile string
	var dsn string
	var logLine string
	var logType string

	var cmdTest = &cobra.Command{
		Use:   "test",
		Short: "Test acquisitions",
		Long: `
Test acquisitions
		`,
		Example: `
cscli test --file ./myfile.log --type nginx 
cscli test --log "Sep 19 18:33:22 scw-d95986 sshd[24347]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4" --type syslog
cscli test -dsn "file://myfile.log" --type nginx
		`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {

			if logType == "" || (logLine == "" && logFile == "" && dsn == "") {
				cmd.Help()
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
			var pdump cstest.ParserResults

			data_fd, err := os.Open("./parser-dump.yaml")
			if err != nil {
				log.Fatal(err)
			}
			defer data_fd.Close()
			//umarshal full gruik
			results, err := ioutil.ReadAll(data_fd)
			if err != nil {
				log.Fatal(err)
			}
			if err := yaml.Unmarshal(results, &pdump); err != nil {
				log.Fatal(err)
			}
			log.Debugf("loaded parsers results %s : %d stages record", "./parser_dump.yaml", len(pdump))
			if err := cstest.DumpParserTree(pdump); err != nil {
				log.Fatalf(err.Error())
			}
		},
	}
	cmdTest.PersistentFlags().StringVarP(&logFile, "file", "f", "", "Log file to test")
	cmdTest.PersistentFlags().StringVarP(&dsn, "dsn", "d", "", "DSN to test")
	cmdTest.PersistentFlags().StringVarP(&logLine, "log", "l", "", "Lgg line to test")
	cmdTest.PersistentFlags().StringVarP(&logType, "type", "t", "", "Type of the acquisition to test")

	return cmdTest
}
