package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/antonmedv/expr"

	"github.com/pkg/errors"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

type OldAPICfg struct {
	MachineID string `json:"machine_id"`
	Password  string `json:"password"`
}

/* Backup crowdsec configurations to directory <dirPath> :

- Main config (config.yaml)
- Profiles config (profiles.yaml)
- Simulation config (simulation.yaml)
- Backup of API credentials (local API and online API)
- List of scenarios, parsers, postoverflows and collections that are up-to-date
- Tainted/local/out-of-date scenarios, parsers, postoverflows and collections
*/
func backupConfigToDirectory(dirPath string) error {
	var err error

	if dirPath == "" {
		return fmt.Errorf("directory path can't be empty")
	}
	log.Infof("Starting configuration backup")
	/*if parent directory doesn't exist, bail out. create final dir with Mkdir*/
	parentDir := filepath.Dir(dirPath)
	if _, err := os.Stat(parentDir); err != nil {
		return errors.Wrapf(err, "while checking parent directory %s existence", parentDir)
	}

	if err = os.Mkdir(dirPath, 0700); err != nil {
		return fmt.Errorf("error while creating %s : %s", dirPath, err)
	}

	if csConfig.ConfigPaths.SimulationFilePath != "" {
		backupSimulation := filepath.Join(dirPath, "simulation.yaml")
		if err = types.CopyFile(csConfig.ConfigPaths.SimulationFilePath, backupSimulation); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", csConfig.ConfigPaths.SimulationFilePath, backupSimulation, err)
		}
		log.Infof("Saved simulation to %s", backupSimulation)
	}

	/*
	   - backup AcquisitionFilePath
	   - backup the other files of acquisition directory
	*/
	if csConfig.Crowdsec != nil && csConfig.Crowdsec.AcquisitionFilePath != "" {
		backupAcquisition := filepath.Join(dirPath, "acquis.yaml")
		if err = types.CopyFile(csConfig.Crowdsec.AcquisitionFilePath, backupAcquisition); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", csConfig.Crowdsec.AcquisitionFilePath, backupAcquisition, err)
		}
	}

	acquisBackupDir := filepath.Join(dirPath, "acquis")
	if err = os.Mkdir(acquisBackupDir, 0700); err != nil {
		return fmt.Errorf("error while creating %s : %s", acquisBackupDir, err)
	}

	if csConfig.Crowdsec != nil && len(csConfig.Crowdsec.AcquisitionFiles) > 0 {
		for _, acquisFile := range csConfig.Crowdsec.AcquisitionFiles {
			/*if it was the default one, it was already backup'ed*/
			if csConfig.Crowdsec.AcquisitionFilePath == acquisFile {
				continue
			}
			targetFname, err := filepath.Abs(filepath.Join(acquisBackupDir, filepath.Base(acquisFile)))
			if err != nil {
				return errors.Wrapf(err, "while saving %s to %s", acquisFile, acquisBackupDir)
			}
			if err = types.CopyFile(acquisFile, targetFname); err != nil {
				return fmt.Errorf("failed copy %s to %s : %s", acquisFile, targetFname, err)
			}
			log.Infof("Saved acquis %s to %s", acquisFile, targetFname)
		}
	}

	if ConfigFilePath != "" {
		backupMain := fmt.Sprintf("%s/config.yaml", dirPath)
		if err = types.CopyFile(ConfigFilePath, backupMain); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", ConfigFilePath, backupMain, err)
		}
		log.Infof("Saved default yaml to %s", backupMain)
	}
	if csConfig.API != nil && csConfig.API.Server != nil && csConfig.API.Server.OnlineClient != nil && csConfig.API.Server.OnlineClient.CredentialsFilePath != "" {
		backupCAPICreds := fmt.Sprintf("%s/online_api_credentials.yaml", dirPath)
		if err = types.CopyFile(csConfig.API.Server.OnlineClient.CredentialsFilePath, backupCAPICreds); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", csConfig.API.Server.OnlineClient.CredentialsFilePath, backupCAPICreds, err)
		}
		log.Infof("Saved online API credentials to %s", backupCAPICreds)
	}
	if csConfig.API != nil && csConfig.API.Client != nil && csConfig.API.Client.CredentialsFilePath != "" {
		backupLAPICreds := fmt.Sprintf("%s/local_api_credentials.yaml", dirPath)
		if err = types.CopyFile(csConfig.API.Client.CredentialsFilePath, backupLAPICreds); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", csConfig.API.Client.CredentialsFilePath, backupLAPICreds, err)
		}
		log.Infof("Saved local API credentials to %s", backupLAPICreds)
	}
	if csConfig.API != nil && csConfig.API.Server != nil && csConfig.API.Server.ProfilesPath != "" {
		backupProfiles := fmt.Sprintf("%s/profiles.yaml", dirPath)
		if err = types.CopyFile(csConfig.API.Server.ProfilesPath, backupProfiles); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", csConfig.API.Server.ProfilesPath, backupProfiles, err)
		}
		log.Infof("Saved profiles to %s", backupProfiles)
	}

	if err = BackupHub(dirPath); err != nil {
		return fmt.Errorf("failed to backup hub config : %s", err)
	}

	return nil
}

/* Restore crowdsec configurations to directory <dirPath> :

- Main config (config.yaml)
- Profiles config (profiles.yaml)
- Simulation config (simulation.yaml)
- Backup of API credentials (local API and online API)
- List of scenarios, parsers, postoverflows and collections that are up-to-date
- Tainted/local/out-of-date scenarios, parsers, postoverflows and collections
*/
func restoreConfigFromDirectory(dirPath string) error {
	var err error

	if !restoreOldBackup {
		backupMain := fmt.Sprintf("%s/config.yaml", dirPath)
		if _, err = os.Stat(backupMain); err == nil {
			if csConfig.ConfigPaths != nil && csConfig.ConfigPaths.ConfigDir != "" {
				if err = types.CopyFile(backupMain, fmt.Sprintf("%s/config.yaml", csConfig.ConfigPaths.ConfigDir)); err != nil {
					return fmt.Errorf("failed copy %s to %s : %s", backupMain, csConfig.ConfigPaths.ConfigDir, err)
				}
			}
		}

		// Now we have config.yaml, we should regenerate config struct to have rights paths etc
		ConfigFilePath = fmt.Sprintf("%s/config.yaml", csConfig.ConfigPaths.ConfigDir)
		initConfig()

		backupCAPICreds := fmt.Sprintf("%s/online_api_credentials.yaml", dirPath)
		if _, err = os.Stat(backupCAPICreds); err == nil {
			if err = types.CopyFile(backupCAPICreds, csConfig.API.Server.OnlineClient.CredentialsFilePath); err != nil {
				return fmt.Errorf("failed copy %s to %s : %s", backupCAPICreds, csConfig.API.Server.OnlineClient.CredentialsFilePath, err)
			}
		}

		backupLAPICreds := fmt.Sprintf("%s/local_api_credentials.yaml", dirPath)
		if _, err = os.Stat(backupLAPICreds); err == nil {
			if err = types.CopyFile(backupLAPICreds, csConfig.API.Client.CredentialsFilePath); err != nil {
				return fmt.Errorf("failed copy %s to %s : %s", backupLAPICreds, csConfig.API.Client.CredentialsFilePath, err)
			}
		}

		backupProfiles := fmt.Sprintf("%s/profiles.yaml", dirPath)
		if _, err = os.Stat(backupProfiles); err == nil {
			if err = types.CopyFile(backupProfiles, csConfig.API.Server.ProfilesPath); err != nil {
				return fmt.Errorf("failed copy %s to %s : %s", backupProfiles, csConfig.API.Server.ProfilesPath, err)
			}
		}
	} else {
		var oldAPICfg OldAPICfg
		backupOldAPICfg := fmt.Sprintf("%s/api_creds.json", dirPath)

		jsonFile, err := os.Open(backupOldAPICfg)
		if err != nil {
			log.Warningf("failed to open %s : %s", backupOldAPICfg, err)
		} else {
			byteValue, _ := ioutil.ReadAll(jsonFile)
			err = json.Unmarshal(byteValue, &oldAPICfg)
			if err != nil {
				return fmt.Errorf("failed to load json file %s : %s", backupOldAPICfg, err)
			}

			apiCfg := csconfig.ApiCredentialsCfg{
				Login:    oldAPICfg.MachineID,
				Password: oldAPICfg.Password,
				URL:      CAPIBaseURL,
			}
			apiConfigDump, err := yaml.Marshal(apiCfg)
			if err != nil {
				return fmt.Errorf("unable to dump api credentials: %s", err)
			}
			apiConfigDumpFile := fmt.Sprintf("%s/online_api_credentials.yaml", csConfig.ConfigPaths.ConfigDir)
			if csConfig.API.Server.OnlineClient != nil && csConfig.API.Server.OnlineClient.CredentialsFilePath != "" {
				apiConfigDumpFile = csConfig.API.Server.OnlineClient.CredentialsFilePath
			}
			err = ioutil.WriteFile(apiConfigDumpFile, apiConfigDump, 0644)
			if err != nil {
				return fmt.Errorf("write api credentials in '%s' failed: %s", apiConfigDumpFile, err)
			}
			log.Infof("Saved API credentials to %s", apiConfigDumpFile)
		}
	}

	backupSimulation := fmt.Sprintf("%s/simulation.yaml", dirPath)
	if _, err = os.Stat(backupSimulation); err == nil {
		if err = types.CopyFile(backupSimulation, csConfig.ConfigPaths.SimulationFilePath); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", backupSimulation, csConfig.ConfigPaths.SimulationFilePath, err)
		}
	}

	/*if there is a acquisition dir, restore its content*/
	if csConfig.Crowdsec.AcquisitionDirPath != "" {
		if err = os.Mkdir(csConfig.Crowdsec.AcquisitionDirPath, 0700); err != nil {
			return fmt.Errorf("error while creating %s : %s", csConfig.Crowdsec.AcquisitionDirPath, err)
		}

	}

	//if there was a single one
	backupAcquisition := fmt.Sprintf("%s/acquis.yaml", dirPath)
	if _, err = os.Stat(backupAcquisition); err == nil {
		log.Debugf("restoring backup'ed %s", backupAcquisition)
		if err = types.CopyFile(backupAcquisition, csConfig.Crowdsec.AcquisitionFilePath); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", backupAcquisition, csConfig.Crowdsec.AcquisitionFilePath, err)
		}
	}

	//if there is files in the acquis backup dir, restore them
	acquisBackupDir := filepath.Join(dirPath, "acquis", "*.yaml")
	if acquisFiles, err := filepath.Glob(acquisBackupDir); err == nil {
		for _, acquisFile := range acquisFiles {
			targetFname, err := filepath.Abs(csConfig.Crowdsec.AcquisitionDirPath + "/" + filepath.Base(acquisFile))
			if err != nil {
				return errors.Wrapf(err, "while saving %s to %s", acquisFile, targetFname)
			}
			log.Debugf("restoring %s to %s", acquisFile, targetFname)
			if err = types.CopyFile(acquisFile, targetFname); err != nil {
				return fmt.Errorf("failed copy %s to %s : %s", acquisFile, targetFname, err)
			}
		}
	}

	if csConfig.Crowdsec != nil && len(csConfig.Crowdsec.AcquisitionFiles) > 0 {
		for _, acquisFile := range csConfig.Crowdsec.AcquisitionFiles {
			log.Infof("backup filepath from dir -> %s", acquisFile)
			/*if it was the default one, it was already backup'ed*/
			if csConfig.Crowdsec.AcquisitionFilePath == acquisFile {
				log.Infof("skip this one")
				continue
			}
			targetFname, err := filepath.Abs(filepath.Join(acquisBackupDir, filepath.Base(acquisFile)))
			if err != nil {
				return errors.Wrapf(err, "while saving %s to %s", acquisFile, acquisBackupDir)
			}
			if err = types.CopyFile(acquisFile, targetFname); err != nil {
				return fmt.Errorf("failed copy %s to %s : %s", acquisFile, targetFname, err)
			}
			log.Infof("Saved acquis %s to %s", acquisFile, targetFname)
		}
	}

	if err = RestoreHub(dirPath); err != nil {
		return fmt.Errorf("failed to restore hub config : %s", err)
	}

	return nil
}

func NewConfigCmd() *cobra.Command {

	var cmdConfig = &cobra.Command{
		Use:               "config [command]",
		Short:             "Allows to view current config",
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
	}
	var key string
	type Env struct {
		Config *csconfig.Config
	}
	var cmdConfigShow = &cobra.Command{
		Use:               "show",
		Short:             "Displays current config",
		Long:              `Displays the current cli configuration.`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {

			if key != "" {
				program, err := expr.Compile(key, expr.Env(Env{}))
				if err != nil {
					log.Fatal(err)
				}
				output, err := expr.Run(program, Env{Config: csConfig})
				if err != nil {
					log.Fatal(err)
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
						log.Fatalf("failed to marshal configuration: %s", err)
					}
					fmt.Printf("%s\n", string(data))
				}
				return
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
					case "mysql", "postgresql", "postgres":
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
	cmdConfigShow.Flags().StringVar(&key, "key", "", "Display only this value (config.API.Server.ListenURI")
	cmdConfig.AddCommand(cmdConfigShow)

	var cmdConfigBackup = &cobra.Command{
		Use:   `backup "directory"`,
		Short: "Backup current config",
		Long: `Backup the current crowdsec configuration including :

- Main config (config.yaml)
- Simulation config (simulation.yaml)
- Profiles config (profiles.yaml)
- List of scenarios, parsers, postoverflows and collections that are up-to-date
- Tainted/local/out-of-date scenarios, parsers, postoverflows and collections
- Backup of API credentials (local API and online API)`,
		Example:           `cscli config backup ./my-backup`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if err := csConfig.LoadHub(); err != nil {
				log.Fatalf(err.Error())
			}
			if err = cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}
			if err = backupConfigToDirectory(args[0]); err != nil {
				log.Fatalf("Failed to backup configurations: %s", err)
			}
		},
	}
	cmdConfig.AddCommand(cmdConfigBackup)

	var cmdConfigRestore = &cobra.Command{
		Use:   `restore "directory"`,
		Short: `Restore config in backup "directory"`,
		Long: `Restore the crowdsec configuration from specified backup "directory" including:

- Main config (config.yaml)
- Simulation config (simulation.yaml)
- Profiles config (profiles.yaml)
- List of scenarios, parsers, postoverflows and collections that are up-to-date
- Tainted/local/out-of-date scenarios, parsers, postoverflows and collections
- Backup of API credentials (local API and online API)`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			if err := csConfig.LoadHub(); err != nil {
				log.Fatalf(err.Error())
			}
			if err = cwhub.GetHubIdx(csConfig.Hub); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
				log.Infoln("Run 'sudo cscli hub update' to get the hub index")
			}
			if err := restoreConfigFromDirectory(args[0]); err != nil {
				log.Fatalf("failed restoring configurations from %s : %s", args[0], err)
			}
		},
	}
	cmdConfigRestore.PersistentFlags().BoolVar(&restoreOldBackup, "old-backup", false, "To use when you are upgrading crowdsec v0.X to v1.X and you need to restore backup from v0.X")
	cmdConfig.AddCommand(cmdConfigRestore)

	return cmdConfig
}
