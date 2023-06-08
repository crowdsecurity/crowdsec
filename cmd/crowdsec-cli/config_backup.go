package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

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

	if err = os.Mkdir(dirPath, 0o700); err != nil {
		return errors.Wrapf(err, "while creating %s", dirPath)
	}

	if csConfig.ConfigPaths.SimulationFilePath != "" {
		backupSimulation := filepath.Join(dirPath, "simulation.yaml")
		if err = CopyFile(csConfig.ConfigPaths.SimulationFilePath, backupSimulation); err != nil {
			return errors.Wrapf(err, "failed copy %s to %s", csConfig.ConfigPaths.SimulationFilePath, backupSimulation)
		}

		log.Infof("Saved simulation to %s", backupSimulation)
	}

	/*
	   - backup AcquisitionFilePath
	   - backup the other files of acquisition directory
	*/
	if csConfig.Crowdsec != nil && csConfig.Crowdsec.AcquisitionFilePath != "" {
		backupAcquisition := filepath.Join(dirPath, "acquis.yaml")
		if err = CopyFile(csConfig.Crowdsec.AcquisitionFilePath, backupAcquisition); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", csConfig.Crowdsec.AcquisitionFilePath, backupAcquisition, err)
		}
	}

	acquisBackupDir := filepath.Join(dirPath, "acquis")
	if err = os.Mkdir(acquisBackupDir, 0o700); err != nil {
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

			if err = CopyFile(acquisFile, targetFname); err != nil {
				return fmt.Errorf("failed copy %s to %s : %s", acquisFile, targetFname, err)
			}

			log.Infof("Saved acquis %s to %s", acquisFile, targetFname)
		}
	}

	if ConfigFilePath != "" {
		backupMain := fmt.Sprintf("%s/config.yaml", dirPath)
		if err = CopyFile(ConfigFilePath, backupMain); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", ConfigFilePath, backupMain, err)
		}

		log.Infof("Saved default yaml to %s", backupMain)
	}

	if csConfig.API != nil && csConfig.API.Server != nil && csConfig.API.Server.OnlineClient != nil && csConfig.API.Server.OnlineClient.CredentialsFilePath != "" {
		backupCAPICreds := fmt.Sprintf("%s/online_api_credentials.yaml", dirPath)
		if err = CopyFile(csConfig.API.Server.OnlineClient.CredentialsFilePath, backupCAPICreds); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", csConfig.API.Server.OnlineClient.CredentialsFilePath, backupCAPICreds, err)
		}

		log.Infof("Saved online API credentials to %s", backupCAPICreds)
	}

	if csConfig.API != nil && csConfig.API.Client != nil && csConfig.API.Client.CredentialsFilePath != "" {
		backupLAPICreds := fmt.Sprintf("%s/local_api_credentials.yaml", dirPath)
		if err = CopyFile(csConfig.API.Client.CredentialsFilePath, backupLAPICreds); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", csConfig.API.Client.CredentialsFilePath, backupLAPICreds, err)
		}

		log.Infof("Saved local API credentials to %s", backupLAPICreds)
	}

	if csConfig.API != nil && csConfig.API.Server != nil && csConfig.API.Server.ProfilesPath != "" {
		backupProfiles := fmt.Sprintf("%s/profiles.yaml", dirPath)
		if err = CopyFile(csConfig.API.Server.ProfilesPath, backupProfiles); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", csConfig.API.Server.ProfilesPath, backupProfiles, err)
		}

		log.Infof("Saved profiles to %s", backupProfiles)
	}

	if err = BackupHub(dirPath); err != nil {
		return fmt.Errorf("failed to backup hub config : %s", err)
	}

	return nil
}


func runConfigBackup(cmd *cobra.Command, args []string) error {
	if err := csConfig.LoadHub(); err != nil {
		return err
	}

	if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
		log.Info("Run 'sudo cscli hub update' to get the hub index")
		return fmt.Errorf("failed to get Hub index: %w", err)
	}

	if err := backupConfigToDirectory(args[0]); err != nil {
		return fmt.Errorf("failed to backup config: %w", err)
	}

	return nil
}


func NewConfigBackupCmd() *cobra.Command {
	cmdConfigBackup := &cobra.Command{
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
		RunE:              runConfigBackup,
	}

	return cmdConfigBackup
}
