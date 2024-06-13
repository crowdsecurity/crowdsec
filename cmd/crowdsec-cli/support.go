package main

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blackfireio/osinfo"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
)

const (
	SUPPORT_METRICS_DIR           = "metrics/"
	SUPPORT_VERSION_PATH          = "version.txt"
	SUPPORT_FEATURES_PATH         = "features.txt"
	SUPPORT_OS_INFO_PATH          = "osinfo.txt"
	SUPPORT_HUB_DIR               = "hub/"
	SUPPORT_BOUNCERS_PATH         = "lapi/bouncers.txt"
	SUPPORT_AGENTS_PATH           = "lapi/agents.txt"
	SUPPORT_CROWDSEC_CONFIG_PATH  = "config/crowdsec.yaml"
	SUPPORT_LAPI_STATUS_PATH      = "lapi_status.txt"
	SUPPORT_CAPI_STATUS_PATH      = "capi_status.txt"
	SUPPORT_ACQUISITION_DIR       = "config/acquis/"
	SUPPORT_CROWDSEC_PROFILE_PATH = "config/profiles.yaml"
	SUPPORT_CRASH_DIR             = "crash/"
	SUPPORT_LOG_DIR               = "log/"
	SUPPORT_PPROF_DIR             = "pprof/"
)

// StringHook collects log entries in a string
type StringHook struct {
	LogBuilder strings.Builder
	LogLevels  []log.Level
}

func (hook *StringHook) Levels() []log.Level {
	return hook.LogLevels
}

func (hook *StringHook) Fire(entry *log.Entry) error {
	logEntry, err := entry.String()
	if err != nil {
		return err
	}

	hook.LogBuilder.WriteString(logEntry)

	return nil
}

// from https://github.com/acarl005/stripansi
var reStripAnsi = regexp.MustCompile("[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))")

func stripAnsiString(str string) string {
	// the byte version doesn't strip correctly
	return reStripAnsi.ReplaceAllString(str, "")
}

func (cli *cliSupport) dumpMetrics(ctx context.Context, zw *zip.Writer) error {
	log.Info("Collecting prometheus metrics")

	cfg := cli.cfg()

	if cfg.Cscli.PrometheusUrl == "" {
		log.Warn("can't collect metrics: prometheus_uri is not set")
	}

	humanMetrics := new(bytes.Buffer)

	ms := NewMetricStore()

	if err := ms.Fetch(cfg.Cscli.PrometheusUrl); err != nil {
		return err
	}

	if err := ms.Format(humanMetrics, nil, "human", false); err != nil {
		return fmt.Errorf("could not format prometheus metrics: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Cscli.PrometheusUrl, nil)
	if err != nil {
		return fmt.Errorf("could not create request to prometheus endpoint: %w", err)
	}

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not get metrics from prometheus endpoint: %w", err)
	}

	defer resp.Body.Close()

	cli.writeToZip(zw, SUPPORT_METRICS_DIR+"metrics.prometheus", time.Now(), resp.Body)

	stripped := stripAnsiString(humanMetrics.String())

	cli.writeToZip(zw, SUPPORT_METRICS_DIR+"metrics.human", time.Now(), strings.NewReader(stripped))

	return nil
}

func (cli *cliSupport) dumpVersion(zw *zip.Writer) {
	log.Info("Collecting version")

	cli.writeToZip(zw, SUPPORT_VERSION_PATH, time.Now(), strings.NewReader(cwversion.FullString()))
}

func (cli *cliSupport) dumpFeatures(zw *zip.Writer) {
	log.Info("Collecting feature flags")

	w := new(bytes.Buffer)
	for _, k := range fflag.Crowdsec.GetEnabledFeatures() {
		fmt.Fprintln(w, k)
	}

	cli.writeToZip(zw, SUPPORT_FEATURES_PATH, time.Now(), w)
}

func (cli *cliSupport) dumpOSInfo(zw *zip.Writer) error {
	log.Info("Collecting OS info")

	info, err := osinfo.GetOSInfo()
	if err != nil {
		return err
	}

	w := new(bytes.Buffer)
	fmt.Fprintf(w, "Architecture: %s\n", info.Architecture)
	fmt.Fprintf(w, "Family: %s\n", info.Family)
	fmt.Fprintf(w, "ID: %s\n", info.ID)
	fmt.Fprintf(w, "Name: %s\n", info.Name)
	fmt.Fprintf(w, "Codename: %s\n", info.Codename)
	fmt.Fprintf(w, "Version: %s\n", info.Version)
	fmt.Fprintf(w, "Build: %s\n", info.Build)

	cli.writeToZip(zw, SUPPORT_OS_INFO_PATH, time.Now(), w)

	return nil
}

func (cli *cliSupport) dumpHubItems(zw *zip.Writer, hub *cwhub.Hub, itemType string) error {
	var err error

	out := new(bytes.Buffer)

	log.Infof("Collecting hub: %s", itemType)

	items := make(map[string][]*cwhub.Item)

	if items[itemType], err = selectItems(hub, itemType, nil, true); err != nil {
		return fmt.Errorf("could not collect %s list: %w", itemType, err)
	}

	if err := listItems(out, []string{itemType}, items, false, "human"); err != nil {
		return fmt.Errorf("could not list %s: %w", itemType, err)
	}

	stripped := stripAnsiString(out.String())

	cli.writeToZip(zw, SUPPORT_HUB_DIR+itemType+".txt", time.Now(), strings.NewReader(stripped))

	return nil
}

func (cli *cliSupport) dumpBouncers(zw *zip.Writer, db *database.Client) error {
	log.Info("Collecting bouncers")

	if db == nil {
		return errors.New("no database connection")
	}

	out := new(bytes.Buffer)

	bouncers, err := db.ListBouncers()
	if err != nil {
		return fmt.Errorf("unable to list bouncers: %w", err)
	}

	getBouncersTable(out, bouncers)

	stripped := stripAnsiString(out.String())

	cli.writeToZip(zw, SUPPORT_BOUNCERS_PATH, time.Now(), strings.NewReader(stripped))

	return nil
}

func (cli *cliSupport) dumpAgents(zw *zip.Writer, db *database.Client) error {
	log.Info("Collecting agents")

	if db == nil {
		return errors.New("no database connection")
	}

	out := new(bytes.Buffer)

	machines, err := db.ListMachines()
	if err != nil {
		return fmt.Errorf("unable to list machines: %w", err)
	}

	getAgentsTable(out, machines)

	stripped := stripAnsiString(out.String())

	cli.writeToZip(zw, SUPPORT_AGENTS_PATH, time.Now(), strings.NewReader(stripped))

	return nil
}

func (cli *cliSupport) dumpLAPIStatus(zw *zip.Writer, hub *cwhub.Hub) error {
	log.Info("Collecting LAPI status")

	cfg := cli.cfg()
	cred := cfg.API.Client.Credentials

	out := new(bytes.Buffer)

	fmt.Fprintf(out, "LAPI credentials file: %s\n", cfg.API.Client.CredentialsFilePath)
	fmt.Fprintf(out, "LAPI URL: %s\n", cred.URL)
	fmt.Fprintf(out, "LAPI username: %s\n", cred.Login)

	if err := QueryLAPIStatus(hub, cred.URL, cred.Login, cred.Password); err != nil {
		return fmt.Errorf("could not authenticate to Local API (LAPI): %w", err)
	}

	fmt.Fprintln(out, "You can successfully interact with Local API (LAPI)")

	cli.writeToZip(zw, SUPPORT_LAPI_STATUS_PATH, time.Now(), out)

	return nil
}

func (cli *cliSupport) dumpCAPIStatus(zw *zip.Writer, hub *cwhub.Hub) error {
	log.Info("Collecting CAPI status")

	cfg := cli.cfg()
	cred := cfg.API.Server.OnlineClient.Credentials

	out := new(bytes.Buffer)

	fmt.Fprintf(out, "CAPI credentials file: %s\n", cfg.API.Server.OnlineClient.CredentialsFilePath)
	fmt.Fprintf(out, "CAPI URL: %s\n", cred.URL)
	fmt.Fprintf(out, "CAPI username: %s\n", cred.Login)

	if err := QueryCAPIStatus(hub, cred.URL, cred.Login, cred.Password); err != nil {
		return fmt.Errorf("could not authenticate to Central API (CAPI): %w", err)
	}

	fmt.Fprintln(out, "You can successfully interact with Central API (CAPI)")

	cli.writeToZip(zw, SUPPORT_CAPI_STATUS_PATH, time.Now(), out)

	return nil
}

func (cli *cliSupport) dumpConfigYAML(zw *zip.Writer) error {
	log.Info("Collecting crowdsec config")

	cfg := cli.cfg()

	config, err := os.ReadFile(*cfg.FilePath)
	if err != nil {
		return fmt.Errorf("could not read config file: %w", err)
	}

	r := regexp.MustCompile(`(\s+password:|\s+user:|\s+host:)\s+.*`)

	redacted := r.ReplaceAll(config, []byte("$1 ****REDACTED****"))

	cli.writeToZip(zw, SUPPORT_CROWDSEC_CONFIG_PATH, time.Now(), bytes.NewReader(redacted))

	return nil
}

func (cli *cliSupport) dumpPprof(ctx context.Context, zw *zip.Writer, prometheusCfg csconfig.PrometheusCfg, endpoint string) error {
	log.Infof("Collecting pprof/%s data", endpoint)

	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf(
			"http://%s/debug/pprof/%s?debug=1",
			net.JoinHostPort(
				prometheusCfg.ListenAddr,
				strconv.Itoa(prometheusCfg.ListenPort),
			),
			endpoint,
		),
		nil,
	)
	if err != nil {
		return fmt.Errorf("could not create request to pprof endpoint: %w", err)
	}

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not get pprof data from endpoint: %w", err)
	}

	defer resp.Body.Close()

	cli.writeToZip(zw, SUPPORT_PPROF_DIR+endpoint+".pprof", time.Now(), resp.Body)

	return nil
}

func (cli *cliSupport) dumpProfiles(zw *zip.Writer) {
	log.Info("Collecting crowdsec profile")

	cfg := cli.cfg()
	cli.writeFileToZip(zw, SUPPORT_CROWDSEC_PROFILE_PATH, cfg.API.Server.ProfilesPath)
}

func (cli *cliSupport) dumpAcquisitionConfig(zw *zip.Writer) {
	log.Info("Collecting acquisition config")

	cfg := cli.cfg()

	for _, filename := range cfg.Crowdsec.AcquisitionFiles {
		fname := strings.ReplaceAll(filename, string(filepath.Separator), "___")
		cli.writeFileToZip(zw, SUPPORT_ACQUISITION_DIR+fname, filename)
	}
}

func (cli *cliSupport) dumpLogs(zw *zip.Writer) error {
	log.Info("Collecting CrowdSec logs")

	cfg := cli.cfg()

	logDir := cfg.Common.LogDir

	logFiles, err := filepath.Glob(filepath.Join(logDir, "crowdsec*.log"))
	if err != nil {
		return fmt.Errorf("could not list log files: %w", err)
	}

	for _, filename := range logFiles {
		cli.writeFileToZip(zw, SUPPORT_LOG_DIR+filepath.Base(filename), filename)
	}

	return nil
}

func (cli *cliSupport) dumpCrash(zw *zip.Writer) error {
	log.Info("Collecting crash dumps")

	traceFiles, err := trace.List()
	if err != nil {
		return fmt.Errorf("could not list crash dumps: %w", err)
	}

	for _, filename := range traceFiles {
		cli.writeFileToZip(zw, SUPPORT_CRASH_DIR+filepath.Base(filename), filename)
	}

	return nil
}

type cliSupport struct {
	cfg configGetter
}

func NewCLISupport(cfg configGetter) *cliSupport {
	return &cliSupport{
		cfg: cfg,
	}
}

func (cli *cliSupport) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "support [action]",
		Short:             "Provide commands to help during support",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(cli.NewDumpCmd())

	return cmd
}

// writeToZip adds a file to the zip archive, from a reader
func (cli *cliSupport) writeToZip(zipWriter *zip.Writer, filename string, mtime time.Time, reader io.Reader) {
	header := &zip.FileHeader{
		Name:     filename,
		Method:   zip.Deflate,
		Modified: mtime,
	}

	fw, err := zipWriter.CreateHeader(header)
	if err != nil {
		log.Errorf("could not add zip entry for %s: %s", filename, err)
		return
	}

	_, err = io.Copy(fw, reader)
	if err != nil {
		log.Errorf("could not write zip entry for %s: %s", filename, err)
	}
}

// writeFileToZip adds a file to the zip archive, from a file, and retains the mtime
func (cli *cliSupport) writeFileToZip(zw *zip.Writer, filename string, fromFile string) {
	mtime := time.Now()

	fi, err := os.Stat(fromFile)
	if err == nil {
		mtime = fi.ModTime()
	}

	fin, err := os.Open(fromFile)
	if err != nil {
		log.Errorf("could not open file %s: %s", fromFile, err)
		return
	}
	defer fin.Close()

	cli.writeToZip(zw, filename, mtime, fin)
}

func (cli *cliSupport) dump(ctx context.Context, outFile string) error {
	var skipCAPI, skipLAPI, skipAgent bool

	collector := &StringHook{
		LogLevels: log.AllLevels,
	}
	log.AddHook(collector)

	cfg := cli.cfg()

	if outFile == "" {
		outFile = filepath.Join(os.TempDir(), "crowdsec-support.zip")
	}

	w := bytes.NewBuffer(nil)
	zipWriter := zip.NewWriter(w)

	db, err := require.DBClient(ctx, cfg.DbConfig)
	if err != nil {
		log.Warn(err)
	}

	if err = cfg.LoadAPIServer(true); err != nil {
		log.Warnf("could not load LAPI, skipping CAPI check")

		skipCAPI = true
	}

	if err = cfg.LoadCrowdsec(); err != nil {
		log.Warnf("could not load agent config, skipping crowdsec config check")

		skipAgent = true
	}

	hub, err := require.Hub(cfg, nil, nil)
	if err != nil {
		log.Warn("Could not init hub, running on LAPI ? Hub related information will not be collected")
		// XXX: lapi status check requires scenarios, will return an error
	}

	if cfg.API.Client == nil || cfg.API.Client.Credentials == nil {
		log.Warn("no agent credentials found, skipping LAPI connectivity check")

		skipLAPI = true
	}

	if cfg.API.Server == nil || cfg.API.Server.OnlineClient == nil || cfg.API.Server.OnlineClient.Credentials == nil {
		log.Warn("no CAPI credentials found, skipping CAPI connectivity check")

		skipCAPI = true
	}

	if err = cli.dumpMetrics(ctx, zipWriter); err != nil {
		log.Warn(err)
	}

	if err = cli.dumpOSInfo(zipWriter); err != nil {
		log.Warnf("could not collect OS information: %s", err)
	}

	if err = cli.dumpConfigYAML(zipWriter); err != nil {
		log.Warnf("could not collect main config file: %s", err)
	}

	if hub != nil {
		for _, itemType := range cwhub.ItemTypes {
			if err = cli.dumpHubItems(zipWriter, hub, itemType); err != nil {
				log.Warnf("could not collect %s information: %s", itemType, err)
			}
		}
	}

	if err = cli.dumpBouncers(zipWriter, db); err != nil {
		log.Warnf("could not collect bouncers information: %s", err)
	}

	if err = cli.dumpAgents(zipWriter, db); err != nil {
		log.Warnf("could not collect agents information: %s", err)
	}

	if !skipCAPI {
		if err = cli.dumpCAPIStatus(zipWriter, hub); err != nil {
			log.Warnf("could not collect CAPI status: %s", err)
		}
	}

	if !skipLAPI {
		if err = cli.dumpLAPIStatus(zipWriter, hub); err != nil {
			log.Warnf("could not collect LAPI status: %s", err)
		}

		// call pprof separately, one might fail for timeout

		if err = cli.dumpPprof(ctx, zipWriter, *cfg.Prometheus, "goroutine"); err != nil {
			log.Warnf("could not collect pprof goroutine data: %s", err)
		}

		if err = cli.dumpPprof(ctx, zipWriter, *cfg.Prometheus, "heap"); err != nil {
			log.Warnf("could not collect pprof heap data: %s", err)
		}

		if err = cli.dumpPprof(ctx, zipWriter, *cfg.Prometheus, "profile"); err != nil {
			log.Warnf("could not collect pprof cpu data: %s", err)
		}

		cli.dumpProfiles(zipWriter)
	}

	if !skipAgent {
		cli.dumpAcquisitionConfig(zipWriter)
	}

	if err = cli.dumpCrash(zipWriter); err != nil {
		log.Warnf("could not collect crash dumps: %s", err)
	}

	if err = cli.dumpLogs(zipWriter); err != nil {
		log.Warnf("could not collect log files: %s", err)
	}

	cli.dumpVersion(zipWriter)
	cli.dumpFeatures(zipWriter)

	// log of the dump process, without color codes
	collectedOutput := stripAnsiString(collector.LogBuilder.String())

	cli.writeToZip(zipWriter, "dump.log", time.Now(), strings.NewReader(collectedOutput))

	err = zipWriter.Close()
	if err != nil {
		return fmt.Errorf("could not finalize zip file: %w", err)
	}

	if outFile == "-" {
		_, err = os.Stdout.Write(w.Bytes())
		return err
	}

	err = os.WriteFile(outFile, w.Bytes(), 0o600)
	if err != nil {
		return fmt.Errorf("could not write zip file to %s: %w", outFile, err)
	}

	log.Infof("Written zip file to %s", outFile)

	return nil
}

func (cli *cliSupport) NewDumpCmd() *cobra.Command {
	var outFile string

	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Dump all your configuration to a zip file for easier support",
		Long: `Dump the following information:
- Crowdsec version
- OS version
- Enabled feature flags
- Latest Crowdsec logs (log processor, LAPI, remediation components)
- Installed collections, parsers, scenarios...
- Bouncers and machines list
- CAPI/LAPI status
- Crowdsec config (sensitive information like username and password are redacted)
- Crowdsec metrics
- Stack trace in case of process crash`,
		Example: `cscli support dump
cscli support dump -f /tmp/crowdsec-support.zip
`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cli.dump(cmd.Context(), outFile)
		},
	}

	cmd.Flags().StringVarP(&outFile, "outFile", "f", "", "File to dump the information to")

	return cmd
}
