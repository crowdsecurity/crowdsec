package main

import (
	"encoding/json"
	"fmt"

	"github.com/antonmedv/expr"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func showConfigKey(key string) error {
	type Env struct {
		Config *csconfig.Config
	}

	program, err := expr.Compile(key, expr.Env(Env{}))
	if err != nil {
		return err
	}

	output, err := expr.Run(program, Env{Config: csConfig})
	if err != nil {
		return err
	}

	switch csConfig.Cscli.Output {
	case "human", "raw":
		switch output.(type) {
		case string:
			fmt.Printf("%s\n", output)
		case int:
			fmt.Printf("%d\n", output)
		default:
			fmt.Printf("%v\n", output)
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

func runConfigShow(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	key, err := flags.GetString("key")
	if err != nil {
		return err
	}

	if key != "" {
		return showConfigKey(key)
	}

	switch csConfig.Cscli.Output {
	case "human":
		fmt.Printf("Global:\n")

		if csConfig.ConfigPaths != nil {
			fmt.Printf("   - Configuration Folder   : %s\n", csConfig.ConfigPaths.ConfigDir)
			fmt.Printf("   - Data Folder            : %s\n", csConfig.ConfigPaths.DataDir)
			fmt.Printf("   - Hub Folder             : %s\n", csConfig.ConfigPaths.HubDir)
			fmt.Printf("   - Simulation File        : %s\n", csConfig.ConfigPaths.SimulationFilePath)
		}

		if csConfig.Common != nil {
			fmt.Printf("   - Log Folder             : %s\n", csConfig.Common.LogDir)
			fmt.Printf("   - Log level              : %s\n", csConfig.Common.LogLevel)
			fmt.Printf("   - Log Media              : %s\n", csConfig.Common.LogMedia)
		}

		if csConfig.Crowdsec != nil {
			fmt.Printf("Crowdsec:\n")
			fmt.Printf("  - Acquisition File        : %s\n", csConfig.Crowdsec.AcquisitionFilePath)
			fmt.Printf("  - Parsers routines        : %d\n", csConfig.Crowdsec.ParserRoutinesCount)
			if csConfig.Crowdsec.AcquisitionDirPath != "" {
				fmt.Printf("  - Acquisition Folder      : %s\n", csConfig.Crowdsec.AcquisitionDirPath)
			}
		}

		if csConfig.Cscli != nil {
			fmt.Printf("cscli:\n")
			fmt.Printf("  - Output                  : %s\n", csConfig.Cscli.Output)
			fmt.Printf("  - Hub Branch              : %s\n", csConfig.Cscli.HubBranch)
			fmt.Printf("  - Hub Folder              : %s\n", csConfig.Cscli.HubDir)
		}

		if csConfig.API != nil {
			if csConfig.API.Client != nil && csConfig.API.Client.Credentials != nil {
				fmt.Printf("API Client:\n")
				fmt.Printf("  - URL                     : %s\n", csConfig.API.Client.Credentials.URL)
				fmt.Printf("  - Login                   : %s\n", csConfig.API.Client.Credentials.Login)
				fmt.Printf("  - Credentials File        : %s\n", csConfig.API.Client.CredentialsFilePath)
			}

			if csConfig.API.Server != nil {
				fmt.Printf("Local API Server:\n")
				fmt.Printf("  - Listen URL              : %s\n", csConfig.API.Server.ListenURI)
				fmt.Printf("  - Profile File            : %s\n", csConfig.API.Server.ProfilesPath)

				if csConfig.API.Server.TLS != nil {
					if csConfig.API.Server.TLS.CertFilePath != "" {
						fmt.Printf("  - Cert File : %s\n", csConfig.API.Server.TLS.CertFilePath)
					}

					if csConfig.API.Server.TLS.KeyFilePath != "" {
						fmt.Printf("  - Key File  : %s\n", csConfig.API.Server.TLS.KeyFilePath)
					}

					if csConfig.API.Server.TLS.CACertPath != "" {
						fmt.Printf("  - CA Cert   : %s\n", csConfig.API.Server.TLS.CACertPath)
					}

					if csConfig.API.Server.TLS.CRLPath != "" {
						fmt.Printf("  - CRL       : %s\n", csConfig.API.Server.TLS.CRLPath)
					}

					if csConfig.API.Server.TLS.CacheExpiration != nil {
						fmt.Printf("  - Cache Expiration : %s\n", csConfig.API.Server.TLS.CacheExpiration)
					}

					if csConfig.API.Server.TLS.ClientVerification != "" {
						fmt.Printf("  - Client Verification : %s\n", csConfig.API.Server.TLS.ClientVerification)
					}

					if csConfig.API.Server.TLS.AllowedAgentsOU != nil {
						for _, ou := range csConfig.API.Server.TLS.AllowedAgentsOU {
							fmt.Printf("      - Allowed Agents OU       : %s\n", ou)
						}
					}

					if csConfig.API.Server.TLS.AllowedBouncersOU != nil {
						for _, ou := range csConfig.API.Server.TLS.AllowedBouncersOU {
							fmt.Printf("      - Allowed Bouncers OU       : %s\n", ou)
						}
					}
				}

				fmt.Printf("  - Trusted IPs: \n")

				for _, ip := range csConfig.API.Server.TrustedIPs {
					fmt.Printf("      - %s\n", ip)
				}

				if csConfig.API.Server.OnlineClient != nil && csConfig.API.Server.OnlineClient.Credentials != nil {
					fmt.Printf("Central API:\n")
					fmt.Printf("  - URL                     : %s\n", csConfig.API.Server.OnlineClient.Credentials.URL)
					fmt.Printf("  - Login                   : %s\n", csConfig.API.Server.OnlineClient.Credentials.Login)
					fmt.Printf("  - Credentials File        : %s\n", csConfig.API.Server.OnlineClient.CredentialsFilePath)
				}
			}
		}

		if csConfig.DbConfig != nil {
			fmt.Printf("  - Database:\n")
			fmt.Printf("      - Type                : %s\n", csConfig.DbConfig.Type)

			switch csConfig.DbConfig.Type {
			case "sqlite":
				fmt.Printf("      - Path                : %s\n", csConfig.DbConfig.DbPath)
			default:
				fmt.Printf("      - Host                : %s\n", csConfig.DbConfig.Host)
				fmt.Printf("      - Port                : %d\n", csConfig.DbConfig.Port)
				fmt.Printf("      - User                : %s\n", csConfig.DbConfig.User)
				fmt.Printf("      - DB Name             : %s\n", csConfig.DbConfig.DbName)
			}

			if csConfig.DbConfig.Flush != nil {
				if *csConfig.DbConfig.Flush.MaxAge != "" {
					fmt.Printf("      - Flush age           : %s\n", *csConfig.DbConfig.Flush.MaxAge)
				}
				if *csConfig.DbConfig.Flush.MaxItems != 0 {
					fmt.Printf("      - Flush size          : %d\n", *csConfig.DbConfig.Flush.MaxItems)
				}
			}
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
