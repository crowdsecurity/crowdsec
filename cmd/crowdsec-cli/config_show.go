package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/template"

	"github.com/antonmedv/expr"
	"github.com/sanity-io/litter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

func showConfigKey(key string) error {
	type Env struct {
		Config *csconfig.Config
	}

	opts := []expr.Option{}
	opts = append(opts, exprhelpers.GetExprOptions(map[string]interface{}{})...)
	opts = append(opts, expr.Env(Env{}))
	program, err := expr.Compile(key, opts...)
	if err != nil {
		return err
	}

	output, err := expr.Run(program, Env{Config: csConfig})
	if err != nil {
		return err
	}

	switch csConfig.Cscli.Output {
	case "human", "raw":
		// Don't use litter for strings, it adds quotes
		// that we didn't have before
		switch output.(type) {
		case string:
			fmt.Println(output)
		default:
			litter.Dump(output)
		}
	case "json":
		data, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal configuration: %w", err)
		}

		fmt.Printf("%s\n", string(data))
	}
	return nil
}

var configShowTemplate = `Global:

{{- if .ConfigPaths }}
   - Configuration Folder   : {{.ConfigPaths.ConfigDir}}
   - Data Folder            : {{.ConfigPaths.DataDir}}
   - Hub Folder             : {{.ConfigPaths.HubDir}}
   - Simulation File        : {{.ConfigPaths.SimulationFilePath}}
{{- end }}

{{- if .Common }}
   - Log Folder             : {{.Common.LogDir}}
   - Log level              : {{.Common.LogLevel}}
   - Log Media              : {{.Common.LogMedia}}
{{- end }}

{{- if .Crowdsec }}
Crowdsec{{if and .Crowdsec.Enable (not (ValueBool .Crowdsec.Enable))}} (disabled){{end}}:
  - Acquisition File        : {{.Crowdsec.AcquisitionFilePath}}
  - Parsers routines        : {{.Crowdsec.ParserRoutinesCount}}
{{- if .Crowdsec.AcquisitionDirPath }}
  - Acquisition Folder      : {{.Crowdsec.AcquisitionDirPath}}
{{- end }}
{{- end }}

{{- if .Cscli }}
cscli:
  - Output                  : {{.Cscli.Output}}
  - Hub Branch              : {{.Cscli.HubBranch}}
{{- end }}

{{- if .API }}
{{- if .API.Client }}
API Client:
{{- if  .API.Client.Credentials }}
  - URL                     : {{.API.Client.Credentials.URL}}
  - Login                   : {{.API.Client.Credentials.Login}}
{{- end }}
  - Credentials File        : {{.API.Client.CredentialsFilePath}}
{{- end }}

{{- if .API.Server }}
Local API Server{{if and .API.Server.Enable (not (ValueBool .API.Server.Enable))}} (disabled){{end}}:
  - Listen URL              : {{.API.Server.ListenURI}}
  - Profile File            : {{.API.Server.ProfilesPath}}

{{- if .API.Server.TLS }}
{{- if .API.Server.TLS.CertFilePath }}
  - Cert File : {{.API.Server.TLS.CertFilePath}}
{{- end }}

{{- if .API.Server.TLS.KeyFilePath }}
  - Key File  : {{.API.Server.TLS.KeyFilePath}}
{{- end }}

{{- if .API.Server.TLS.CACertPath }}
  - CA Cert   : {{.API.Server.TLS.CACertPath}}
{{- end }}

{{- if .API.Server.TLS.CRLPath }}
  - CRL       : {{.API.Server.TLS.CRLPath}}
{{- end }}

{{- if .API.Server.TLS.CacheExpiration }}
  - Cache Expiration : {{.API.Server.TLS.CacheExpiration}}
{{- end }}

{{- if .API.Server.TLS.ClientVerification }}
  - Client Verification : {{.API.Server.TLS.ClientVerification}}
{{- end }}

{{- if .API.Server.TLS.AllowedAgentsOU }}
{{- range .API.Server.TLS.AllowedAgentsOU }}
  - Allowed Agents OU       : {{.}}
{{- end }}
{{- end }}

{{- if .API.Server.TLS.AllowedBouncersOU }}
{{- range .API.Server.TLS.AllowedBouncersOU }}
  - Allowed Bouncers OU       : {{.}}
{{- end }}
{{- end }}
{{- end }}

  - Trusted IPs: 
{{- range .API.Server.TrustedIPs }}
      - {{.}}
{{- end }}

{{- if and .API.Server.OnlineClient .API.Server.OnlineClient.Credentials }}
Central API:
  - URL                     : {{.API.Server.OnlineClient.Credentials.URL}}
  - Login                   : {{.API.Server.OnlineClient.Credentials.Login}}
  - Credentials File        : {{.API.Server.OnlineClient.CredentialsFilePath}}
{{- end }}
{{- end }}
{{- end }}

{{- if .DbConfig }}
  - Database:
      - Type                : {{.DbConfig.Type}}
{{- if eq .DbConfig.Type "sqlite" }}
      - Path                : {{.DbConfig.DbPath}}
{{- else}}
      - Host                : {{.DbConfig.Host}}
      - Port                : {{.DbConfig.Port}}
      - User                : {{.DbConfig.User}}
      - DB Name             : {{.DbConfig.DbName}}
{{- end }}
{{- if .DbConfig.MaxOpenConns }}
      - Max Open Conns      : {{.DbConfig.MaxOpenConns}}
{{- end }}
{{- if ne .DbConfig.DecisionBulkSize 0 }}
      - Decision Bulk Size  : {{.DbConfig.DecisionBulkSize}}
{{- end }}
{{- if .DbConfig.Flush }}
{{- if .DbConfig.Flush.MaxAge }}
      - Flush age           : {{.DbConfig.Flush.MaxAge}}
{{- end }}
{{- if .DbConfig.Flush.MaxItems }}
      - Flush size          : {{.DbConfig.Flush.MaxItems}}
{{- end }}
{{- end }}
{{- end }}
`

func runConfigShow(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	if err := csConfig.LoadAPIClient(); err != nil {
		log.Errorf("failed to load API client configuration: %s", err)
		// don't return, we can still show the configuration
	}

	key, err := flags.GetString("key")
	if err != nil {
		return err
	}

	if key != "" {
		return showConfigKey(key)
	}

	switch csConfig.Cscli.Output {
	case "human":
		// The tests on .Enable look funny because the option has a true default which has
		// not been set yet (we don't really load the LAPI) and go templates don't dereference
		// pointers in boolean tests. Prefix notation is the cherry on top.
		funcs := template.FuncMap{
			// can't use generics here
			"ValueBool": func(b *bool) bool { return b!=nil && *b },
		}

		tmp, err := template.New("config").Funcs(funcs).Parse(configShowTemplate)
		if err != nil {
			return err
		}
		err = tmp.Execute(os.Stdout, csConfig)
		if err != nil {
			return err
		}
	case "json":
		data, err := json.MarshalIndent(csConfig, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal configuration: %w", err)
		}

		fmt.Printf("%s\n", string(data))
	case "raw":
		data, err := yaml.Marshal(csConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal configuration: %w", err)
		}

		fmt.Printf("%s\n", string(data))
	}
	return nil
}

func NewConfigShowCmd() *cobra.Command {
	cmdConfigShow := &cobra.Command{
		Use:               "show",
		Short:             "Displays current config",
		Long:              `Displays the current cli configuration.`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE:              runConfigShow,
	}

	flags := cmdConfigShow.Flags()
	flags.StringP("key", "", "", "Display only this value (Config.API.Server.ListenURI)")

	return cmdConfigShow
}
