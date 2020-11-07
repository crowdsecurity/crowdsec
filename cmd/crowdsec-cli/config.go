package main

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func NewConfigCmd() *cobra.Command {

	var cmdConfig = &cobra.Command{
		Use:   "config [command]",
		Short: "Allows to view current config",
		Args:  cobra.ExactArgs(0),
	}
	var cmdConfigShow = &cobra.Command{
		Use:   "show",
		Short: "Displays current config",
		Long:  `Displays the current cli configuration.`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			switch csConfig.Cscli.Output {
			case "human":
				fmt.Printf("Global:\n")
				fmt.Printf("   - Configuration Folder   : %s\n", csConfig.ConfigPaths.ConfigDir)
				fmt.Printf("   - Data Folder            : %s\n", csConfig.ConfigPaths.DataDir)
				fmt.Printf("   - Log Folder             : %s\n", csConfig.Common.LogDir)
				fmt.Printf("   - Hub Folder             : %s\n", csConfig.ConfigPaths.HubDir)
				fmt.Printf("   - Simulation File        : %s\n", csConfig.ConfigPaths.SimulationFilePath)
				fmt.Printf("   - Log level              : %s\n", csConfig.Common.LogLevel)
				fmt.Printf("   - Log Media              : %s\n", csConfig.Common.LogMedia)
				fmt.Printf("Crowdsec:\n")
				fmt.Printf("  - Acquisition File        : %s\n", csConfig.Crowdsec.AcquisitionFilePath)
				fmt.Printf("  - Parsers routines        : %d\n", csConfig.Crowdsec.ParserRoutinesCount)
				fmt.Printf("API Client:\n")
				fmt.Printf("  - URL                     : %s\n", csConfig.API.Client.Credentials.URL)
				fmt.Printf("  - Login                   : %s\n", csConfig.API.Client.Credentials.Login)
				fmt.Printf("  - Credentials File        : %s\n", csConfig.API.Client.CredentialsFilePath)
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
				}
				fmt.Printf("  - Database:\n")
				fmt.Printf("      - Type                : %s\n", csConfig.DbConfig.Type)
				switch csConfig.DbConfig.Type {
				case "sqlite":
					fmt.Printf("      - Path                : %s\n", csConfig.DbConfig.DbPath)
				case "mysql", "postgresql", "postegres":
					fmt.Printf("      - Host                : %s\n", csConfig.DbConfig.DbPath)
					fmt.Printf("      - Port                : %s\n", csConfig.DbConfig.DbPath)
					fmt.Printf("      - User                : %s\n", csConfig.DbConfig.DbPath)
					fmt.Printf("      - DB Name             : %s\n", csConfig.DbConfig.DbPath)
				}
				fmt.Printf("Central API:\n")
				fmt.Printf("  - URL                     : %s\n", csConfig.API.Server.OnlineClient.Credentials.URL)
				fmt.Printf("  - Login                   : %s\n", csConfig.API.Server.OnlineClient.Credentials.Login)
				fmt.Printf("  - Credentials File        : %s\n", csConfig.API.Server.OnlineClient.CredentialsFilePath)
			case "json":
				data, err := json.MarshalIndent(csConfig, "", "  ")
				if err != nil {
					log.Fatalf("failed to marshal configuration: %s", err)
				}
				fmt.Printf("%s\n", string(data))
			case "raw":
				data, err := yaml.Marshal(csConfig)
				if err != nil {
					log.Fatalf("failed to marshal configuration: %s", err)
				}
				fmt.Printf("%s\n", string(data))
			}
		},
	}
	cmdConfig.AddCommand(cmdConfigShow)
	return cmdConfig
}
