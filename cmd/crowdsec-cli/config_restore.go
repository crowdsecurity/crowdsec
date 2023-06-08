package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

type OldAPICfg struct {
	MachineID string `json:"machine_id"`
	Password  string `json:"password"`
}

/* Restore crowdsec configurations to directory <dirPath> :

- Main config (config.yaml)
- Profiles config (profiles.yaml)
- Simulation config (simulation.yaml)
- Backup of API credentials (local API and online API)
- List of scenarios, parsers, postoverflows and collections that are up-to-date
- Tainted/local/out-of-date scenarios, parsers, postoverflows and collections
*/
func restoreConfigFromDirectory(dirPath string, oldBackup bool) error {
	var err error

	if !oldBackup {
		backupMain := fmt.Sprintf("%s/config.yaml", dirPath)
		if _, err = os.Stat(backupMain); err == nil {
			if csConfig.ConfigPaths != nil && csConfig.ConfigPaths.ConfigDir != "" {
				if err = CopyFile(backupMain, fmt.Sprintf("%s/config.yaml", csConfig.ConfigPaths.ConfigDir)); err != nil {
					return fmt.Errorf("failed copy %s to %s : %s", backupMain, csConfig.ConfigPaths.ConfigDir, err)
				}
			}
		}

		// Now we have config.yaml, we should regenerate config struct to have rights paths etc
		ConfigFilePath = fmt.Sprintf("%s/config.yaml", csConfig.ConfigPaths.ConfigDir)

		initConfig()

		backupCAPICreds := fmt.Sprintf("%s/online_api_credentials.yaml", dirPath)
		if _, err = os.Stat(backupCAPICreds); err == nil {
			if err = CopyFile(backupCAPICreds, csConfig.API.Server.OnlineClient.CredentialsFilePath); err != nil {
				return fmt.Errorf("failed copy %s to %s : %s", backupCAPICreds, csConfig.API.Server.OnlineClient.CredentialsFilePath, err)
			}
		}

		backupLAPICreds := fmt.Sprintf("%s/local_api_credentials.yaml", dirPath)
		if _, err = os.Stat(backupLAPICreds); err == nil {
			if err = CopyFile(backupLAPICreds, csConfig.API.Client.CredentialsFilePath); err != nil {
				return fmt.Errorf("failed copy %s to %s : %s", backupLAPICreds, csConfig.API.Client.CredentialsFilePath, err)
			}
		}

		backupProfiles := fmt.Sprintf("%s/profiles.yaml", dirPath)
		if _, err = os.Stat(backupProfiles); err == nil {
			if err = CopyFile(backupProfiles, csConfig.API.Server.ProfilesPath); err != nil {
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
			byteValue, _ := io.ReadAll(jsonFile)
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
			err = os.WriteFile(apiConfigDumpFile, apiConfigDump, 0o644)
			if err != nil {
				return fmt.Errorf("write api credentials in '%s' failed: %s", apiConfigDumpFile, err)
			}
			log.Infof("Saved API credentials to %s", apiConfigDumpFile)
		}
	}

	backupSimulation := fmt.Sprintf("%s/simulation.yaml", dirPath)
	if _, err = os.Stat(backupSimulation); err == nil {
		if err = CopyFile(backupSimulation, csConfig.ConfigPaths.SimulationFilePath); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", backupSimulation, csConfig.ConfigPaths.SimulationFilePath, err)
		}
	}

	/*if there is a acquisition dir, restore its content*/
	if csConfig.Crowdsec.AcquisitionDirPath != "" {
		if err = os.Mkdir(csConfig.Crowdsec.AcquisitionDirPath, 0o700); err != nil {
			return fmt.Errorf("error while creating %s : %s", csConfig.Crowdsec.AcquisitionDirPath, err)
		}
	}

	// if there was a single one
	backupAcquisition := fmt.Sprintf("%s/acquis.yaml", dirPath)
	if _, err = os.Stat(backupAcquisition); err == nil {
		log.Debugf("restoring backup'ed %s", backupAcquisition)

		if err = CopyFile(backupAcquisition, csConfig.Crowdsec.AcquisitionFilePath); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", backupAcquisition, csConfig.Crowdsec.AcquisitionFilePath, err)
		}
	}

	// if there is files in the acquis backup dir, restore them
	acquisBackupDir := filepath.Join(dirPath, "acquis", "*.yaml")
	if acquisFiles, err := filepath.Glob(acquisBackupDir); err == nil {
		for _, acquisFile := range acquisFiles {
			targetFname, err := filepath.Abs(csConfig.Crowdsec.AcquisitionDirPath + "/" + filepath.Base(acquisFile))
			if err != nil {
				return errors.Wrapf(err, "while saving %s to %s", acquisFile, targetFname)
			}

			log.Debugf("restoring %s to %s", acquisFile, targetFname)

			if err = CopyFile(acquisFile, targetFname); err != nil {
				return fmt.Errorf("failed copy %s to %s : %s", acquisFile, targetFname, err)
			}
		}
	}

	if csConfig.Crowdsec != nil && len(csConfig.Crowdsec.AcquisitionFiles) > 0 {
		for _, acquisFile := range csConfig.Crowdsec.AcquisitionFiles {
			log.Infof("backup filepath from dir -> %s", acquisFile)

			// if it was the default one, it has already been backed up
			if csConfig.Crowdsec.AcquisitionFilePath == acquisFile {
				log.Infof("skip this one")
				continue
			}

			targetFname, err := filepath.Abs(filepath.Join(acquisBackupDir, filepath.Base(acquisFile)))
			if err != nil {
				return errors.Wrapf(err, "while saving %s to %s", acquisFile, acquisBackupDir)
			}

			if err = CopyFile(acquisFile, targetFname); err != nil {
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


func runConfigRestore(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	oldBackup, err := flags.GetBool("old-backup")
	if err != nil {
		return err
	}

	if err := csConfig.LoadHub(); err != nil {
		return err
	}

	if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
		log.Info("Run 'sudo cscli hub update' to get the hub index")
		return fmt.Errorf("failed to get Hub index: %w", err)
	}

	if err := restoreConfigFromDirectory(args[0], oldBackup); err != nil {
		return fmt.Errorf("failed to restore config from %s: %w", args[0], err)
	}

	return nil
}


func NewConfigRestoreCmd() *cobra.Command {
	cmdConfigRestore := &cobra.Command{
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
		RunE:              runConfigRestore,
	}

	flags := cmdConfigRestore.Flags()
	flags.BoolP("old-backup", "", false, "To use when you are upgrading crowdsec v0.X to v1.X and you need to restore backup from v0.X")

	return cmdConfigRestore
}
