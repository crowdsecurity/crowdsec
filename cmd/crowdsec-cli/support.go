package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blackfireio/osinfo"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

const (
	SUPPORT_METRICS_HUMAN_PATH           = "metrics/metrics.human"
	SUPPORT_METRICS_PROMETHEUS_PATH      = "metrics/metrics.prometheus"
	SUPPORT_VERSION_PATH                 = "version.txt"
	SUPPORT_FEATURES_PATH                = "features.txt"
	SUPPORT_OS_INFO_PATH                 = "osinfo.txt"
	SUPPORT_PARSERS_PATH                 = "hub/parsers.txt"
	SUPPORT_SCENARIOS_PATH               = "hub/scenarios.txt"
	SUPPORT_CONTEXTS_PATH                = "hub/scenarios.txt"
	SUPPORT_COLLECTIONS_PATH             = "hub/collections.txt"
	SUPPORT_POSTOVERFLOWS_PATH           = "hub/postoverflows.txt"
	SUPPORT_BOUNCERS_PATH                = "lapi/bouncers.txt"
	SUPPORT_AGENTS_PATH                  = "lapi/agents.txt"
	SUPPORT_CROWDSEC_CONFIG_PATH         = "config/crowdsec.yaml"
	SUPPORT_LAPI_STATUS_PATH             = "lapi_status.txt"
	SUPPORT_CAPI_STATUS_PATH             = "capi_status.txt"
	SUPPORT_ACQUISITION_CONFIG_BASE_PATH = "config/acquis/"
	SUPPORT_CROWDSEC_PROFILE_PATH        = "config/profiles.yaml"
)

// from https://github.com/acarl005/stripansi
var reStripAnsi = regexp.MustCompile("[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))")

func stripAnsiString(str string) string {
	// the byte version doesn't strip correctly
	return reStripAnsi.ReplaceAllString(str, "")
}

func collectMetrics() ([]byte, []byte, error) {
	log.Info("Collecting prometheus metrics")

	if csConfig.Cscli.PrometheusUrl == "" {
		log.Warn("No Prometheus URL configured, metrics will not be collected")
		return nil, nil, fmt.Errorf("prometheus_uri is not set")
	}

	humanMetrics := bytes.NewBuffer(nil)
	err := FormatPrometheusMetrics(humanMetrics, csConfig.Cscli.PrometheusUrl, "human")

	if err != nil {
		return nil, nil, fmt.Errorf("could not fetch promtheus metrics: %s", err)
	}

	req, err := http.NewRequest(http.MethodGet, csConfig.Cscli.PrometheusUrl, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create requests to prometheus endpoint: %s", err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		return nil, nil, fmt.Errorf("could not get metrics from prometheus endpoint: %s", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read metrics from prometheus endpoint: %s", err)
	}

	return humanMetrics.Bytes(), body, nil
}

func collectVersion() []byte {
	log.Info("Collecting version")
	return []byte(cwversion.ShowStr())
}

func collectFeatures() []byte {
	log.Info("Collecting feature flags")
	enabledFeatures := fflag.Crowdsec.GetEnabledFeatures()

	w := bytes.NewBuffer(nil)
	for _, k := range enabledFeatures {
		fmt.Fprintf(w, "%s\n", k)
	}
	return w.Bytes()
}

func collectOSInfo() ([]byte, error) {
	log.Info("Collecting OS info")
	info, err := osinfo.GetOSInfo()

	if err != nil {
		return nil, err
	}

	w := bytes.NewBuffer(nil)
	w.WriteString(fmt.Sprintf("Architecture: %s\n", info.Architecture))
	w.WriteString(fmt.Sprintf("Family: %s\n", info.Family))
	w.WriteString(fmt.Sprintf("ID: %s\n", info.ID))
	w.WriteString(fmt.Sprintf("Name: %s\n", info.Name))
	w.WriteString(fmt.Sprintf("Codename: %s\n", info.Codename))
	w.WriteString(fmt.Sprintf("Version: %s\n", info.Version))
	w.WriteString(fmt.Sprintf("Build: %s\n", info.Build))

	return w.Bytes(), nil
}

func collectHubItems(hub *cwhub.Hub, itemType string) []byte {
	var err error

	out := bytes.NewBuffer(nil)
	log.Infof("Collecting %s list", itemType)

	items := make(map[string][]*cwhub.Item)

	if items[itemType], err = selectItems(hub, itemType, nil, true); err != nil {
		log.Warnf("could not collect %s list: %s", itemType, err)
	}

	if err := listItems(out, []string{itemType}, items, false); err != nil {
		log.Warnf("could not collect %s list: %s", itemType, err)
	}
	return out.Bytes()
}

func collectBouncers(dbClient *database.Client) ([]byte, error) {
	out := bytes.NewBuffer(nil)
	err := getBouncers(out, dbClient)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func collectAgents(dbClient *database.Client) ([]byte, error) {
	out := bytes.NewBuffer(nil)
	err := getAgents(out, dbClient)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func collectAPIStatus(login string, password string, endpoint string, prefix string, hub *cwhub.Hub) []byte {
	if csConfig.API.Client == nil || csConfig.API.Client.Credentials == nil {
		return []byte("No agent credentials found, are we LAPI ?")
	}
	pwd := strfmt.Password(password)
	apiurl, err := url.Parse(endpoint)

	if err != nil {
		return []byte(fmt.Sprintf("cannot parse API URL: %s", err))
	}
	scenarios, err := hub.GetInstalledItemNames(cwhub.SCENARIOS)
	if err != nil {
		return []byte(fmt.Sprintf("could not collect scenarios: %s", err))
	}

	Client, err = apiclient.NewDefaultClient(apiurl,
		prefix,
		fmt.Sprintf("crowdsec/%s", version.String()),
		nil)
	if err != nil {
		return []byte(fmt.Sprintf("could not init client: %s", err))
	}
	t := models.WatcherAuthRequest{
		MachineID: &login,
		Password:  &pwd,
		Scenarios: scenarios,
	}

	_, _, err = Client.Auth.AuthenticateWatcher(context.Background(), t)
	if err != nil {
		return []byte(fmt.Sprintf("Could not authenticate to API: %s", err))
	} else {
		return []byte("Successfully authenticated to LAPI")
	}
}

func collectCrowdsecConfig() []byte {
	log.Info("Collecting crowdsec config")
	config, err := os.ReadFile(*csConfig.FilePath)
	if err != nil {
		return []byte(fmt.Sprintf("could not read config file: %s", err))
	}

	r := regexp.MustCompile(`(\s+password:|\s+user:|\s+host:)\s+.*`)

	return r.ReplaceAll(config, []byte("$1 ****REDACTED****"))
}

func collectCrowdsecProfile() []byte {
	log.Info("Collecting crowdsec profile")
	config, err := os.ReadFile(csConfig.API.Server.ProfilesPath)
	if err != nil {
		return []byte(fmt.Sprintf("could not read profile file: %s", err))
	}
	return config
}

func collectAcquisitionConfig() map[string][]byte {
	log.Info("Collecting acquisition config")
	ret := make(map[string][]byte)

	for _, filename := range csConfig.Crowdsec.AcquisitionFiles {
		fileContent, err := os.ReadFile(filename)
		if err != nil {
			ret[filename] = []byte(fmt.Sprintf("could not read file: %s", err))
		} else {
			ret[filename] = fileContent
		}
	}

	return ret
}

type cliSupport struct{}

func NewCLISupport() *cliSupport {
	return &cliSupport{}
}

func (cli cliSupport) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "support [action]",
		Short:             "Provide commands to help during support",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	cmd.AddCommand(cli.NewDumpCmd())

	return cmd
}

func (cli cliSupport) NewDumpCmd() *cobra.Command {
	var outFile string

	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Dump all your configuration to a zip file for easier support",
		Long: `Dump the following informations:
- Crowdsec version
- OS version
- Installed collections list
- Installed parsers list
- Installed scenarios list
- Installed postoverflows list
- Installed context list
- Bouncers list
- Machines list
- CAPI status
- LAPI status
- Crowdsec config (sensitive information like username and password are redacted)
- Crowdsec metrics`,
		Example: `cscli support dump
cscli support dump -f /tmp/crowdsec-support.zip
`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			var skipHub, skipDB, skipCAPI, skipLAPI, skipAgent bool
			infos := map[string][]byte{
				SUPPORT_VERSION_PATH:  collectVersion(),
				SUPPORT_FEATURES_PATH: collectFeatures(),
			}

			if outFile == "" {
				outFile = "/tmp/crowdsec-support.zip"
			}

			dbClient, err = database.NewClient(csConfig.DbConfig)
			if err != nil {
				log.Warnf("Could not connect to database: %s", err)
				skipDB = true
				infos[SUPPORT_BOUNCERS_PATH] = []byte(err.Error())
				infos[SUPPORT_AGENTS_PATH] = []byte(err.Error())
			}

			if err := csConfig.LoadAPIServer(); err != nil {
				log.Warnf("could not load LAPI, skipping CAPI check")
				skipLAPI = true
				infos[SUPPORT_CAPI_STATUS_PATH] = []byte(err.Error())
			}

			if err := csConfig.LoadCrowdsec(); err != nil {
				log.Warnf("could not load agent config, skipping crowdsec config check")
				skipAgent = true
			}

			hub, err := require.Hub(csConfig, nil, nil)
			if err != nil {
				log.Warn("Could not init hub, running on LAPI ? Hub related information will not be collected")
				skipHub = true
				infos[SUPPORT_PARSERS_PATH] = []byte(err.Error())
				infos[SUPPORT_SCENARIOS_PATH] = []byte(err.Error())
				infos[SUPPORT_POSTOVERFLOWS_PATH] = []byte(err.Error())
				infos[SUPPORT_CONTEXTS_PATH] = []byte(err.Error())
				infos[SUPPORT_COLLECTIONS_PATH] = []byte(err.Error())
			}

			if csConfig.API.Client == nil || csConfig.API.Client.Credentials == nil {
				log.Warn("no agent credentials found, skipping LAPI connectivity check")
				if _, ok := infos[SUPPORT_LAPI_STATUS_PATH]; ok {
					infos[SUPPORT_LAPI_STATUS_PATH] = append(infos[SUPPORT_LAPI_STATUS_PATH], []byte("\nNo LAPI credentials found")...)
				}
				skipLAPI = true
			}

			if csConfig.API.Server == nil || csConfig.API.Server.OnlineClient == nil || csConfig.API.Server.OnlineClient.Credentials == nil {
				log.Warn("no CAPI credentials found, skipping CAPI connectivity check")
				skipCAPI = true
			}

			infos[SUPPORT_METRICS_HUMAN_PATH], infos[SUPPORT_METRICS_PROMETHEUS_PATH], err = collectMetrics()
			if err != nil {
				log.Warnf("could not collect prometheus metrics information: %s", err)
				infos[SUPPORT_METRICS_HUMAN_PATH] = []byte(err.Error())
				infos[SUPPORT_METRICS_PROMETHEUS_PATH] = []byte(err.Error())
			}

			infos[SUPPORT_OS_INFO_PATH], err = collectOSInfo()
			if err != nil {
				log.Warnf("could not collect OS information: %s", err)
				infos[SUPPORT_OS_INFO_PATH] = []byte(err.Error())
			}

			infos[SUPPORT_CROWDSEC_CONFIG_PATH] = collectCrowdsecConfig()

			if !skipHub {
				infos[SUPPORT_PARSERS_PATH] = collectHubItems(hub, cwhub.PARSERS)
				infos[SUPPORT_SCENARIOS_PATH] = collectHubItems(hub, cwhub.SCENARIOS)
				infos[SUPPORT_POSTOVERFLOWS_PATH] = collectHubItems(hub, cwhub.POSTOVERFLOWS)
				infos[SUPPORT_CONTEXTS_PATH] = collectHubItems(hub, cwhub.POSTOVERFLOWS)
				infos[SUPPORT_COLLECTIONS_PATH] = collectHubItems(hub, cwhub.COLLECTIONS)
			}

			if !skipDB {
				infos[SUPPORT_BOUNCERS_PATH], err = collectBouncers(dbClient)
				if err != nil {
					log.Warnf("could not collect bouncers information: %s", err)
					infos[SUPPORT_BOUNCERS_PATH] = []byte(err.Error())
				}

				infos[SUPPORT_AGENTS_PATH], err = collectAgents(dbClient)
				if err != nil {
					log.Warnf("could not collect agents information: %s", err)
					infos[SUPPORT_AGENTS_PATH] = []byte(err.Error())
				}
			}

			if !skipCAPI {
				log.Info("Collecting CAPI status")
				infos[SUPPORT_CAPI_STATUS_PATH] = collectAPIStatus(csConfig.API.Server.OnlineClient.Credentials.Login,
					csConfig.API.Server.OnlineClient.Credentials.Password,
					csConfig.API.Server.OnlineClient.Credentials.URL,
					CAPIURLPrefix,
					hub)
			}

			if !skipLAPI {
				log.Info("Collection LAPI status")
				infos[SUPPORT_LAPI_STATUS_PATH] = collectAPIStatus(csConfig.API.Client.Credentials.Login,
					csConfig.API.Client.Credentials.Password,
					csConfig.API.Client.Credentials.URL,
					LAPIURLPrefix,
					hub)
				infos[SUPPORT_CROWDSEC_PROFILE_PATH] = collectCrowdsecProfile()
			}

			if !skipAgent {

				acquis := collectAcquisitionConfig()

				for filename, content := range acquis {
					fname := strings.ReplaceAll(filename, string(filepath.Separator), "___")
					infos[SUPPORT_ACQUISITION_CONFIG_BASE_PATH+fname] = content
				}
			}

			w := bytes.NewBuffer(nil)
			zipWriter := zip.NewWriter(w)

			for filename, data := range infos {
				fw, err := zipWriter.Create(filename)
				if err != nil {
					log.Errorf("Could not add zip entry for %s: %s", filename, err)
					continue
				}
				fw.Write([]byte(stripAnsiString(string(data))))
			}

			err = zipWriter.Close()
			if err != nil {
				log.Fatalf("could not finalize zip file: %s", err)
			}

			err = os.WriteFile(outFile, w.Bytes(), 0o600)
			if err != nil {
				log.Fatalf("could not write zip file to %s: %s", outFile, err)
			}

			log.Infof("Written zip file to %s", outFile)
		},
	}

	cmd.Flags().StringVarP(&outFile, "outFile", "f", "", "File to dump the information to")

	return cmd
}
