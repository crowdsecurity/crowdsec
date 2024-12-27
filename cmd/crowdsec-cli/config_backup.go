package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func (cli *cliConfig) backupHub(dirPath string) error {
	hub, err := require.Hub(cli.cfg(), nil)
	if err != nil {
		return err
	}

	for _, itemType := range cwhub.ItemTypes {
		clog := log.WithField("type", itemType)

		itemMap := hub.GetItemMap(itemType)
		if itemMap == nil {
			clog.Infof("No %s to backup.", itemType)
			continue
		}

		itemDirectory := fmt.Sprintf("%s/%s/", dirPath, itemType)
		if err = os.MkdirAll(itemDirectory, os.ModePerm); err != nil {
			return fmt.Errorf("error while creating %s: %w", itemDirectory, err)
		}

		upstreamParsers := []string{}

		for k, v := range itemMap {
			clog = clog.WithField("file", v.Name)
			if !v.State.Installed { // only backup installed ones
				clog.Debugf("[%s]: not installed", k)
				continue
			}

			// for the local/tainted ones, we back up the full file
			if v.State.Tainted || v.State.IsLocal() || !v.State.UpToDate {
				// we need to backup stages for parsers
				if itemType == cwhub.PARSERS || itemType == cwhub.POSTOVERFLOWS {
					fstagedir := fmt.Sprintf("%s%s", itemDirectory, v.Stage)
					if err = os.MkdirAll(fstagedir, os.ModePerm); err != nil {
						return fmt.Errorf("error while creating stage dir %s: %w", fstagedir, err)
					}
				}

				clog.Debugf("[%s]: backing up file (tainted:%t local:%t up-to-date:%t)", k, v.State.Tainted, v.State.IsLocal(), v.State.UpToDate)

				tfile := fmt.Sprintf("%s%s/%s", itemDirectory, v.Stage, v.FileName)
				if err = CopyFile(v.State.LocalPath, tfile); err != nil {
					return fmt.Errorf("failed copy %s %s to %s: %w", itemType, v.State.LocalPath, tfile, err)
				}

				clog.Infof("local/tainted saved %s to %s", v.State.LocalPath, tfile)

				continue
			}

			clog.Debugf("[%s]: from hub, just backup name (up-to-date:%t)", k, v.State.UpToDate)
			clog.Infof("saving, version:%s, up-to-date:%t", v.Version, v.State.UpToDate)
			upstreamParsers = append(upstreamParsers, v.Name)
		}
		// write the upstream items
		upstreamParsersFname := fmt.Sprintf("%s/upstream-%s.json", itemDirectory, itemType)

		upstreamParsersContent, err := json.MarshalIndent(upstreamParsers, "", " ")
		if err != nil {
			return fmt.Errorf("failed to serialize upstream parsers: %w", err)
		}

		err = os.WriteFile(upstreamParsersFname, upstreamParsersContent, 0o644)
		if err != nil {
			return fmt.Errorf("unable to write to %s %s: %w", itemType, upstreamParsersFname, err)
		}

		clog.Infof("Wrote %d entries for %s to %s", len(upstreamParsers), itemType, upstreamParsersFname)
	}

	return nil
}

/*
	Backup crowdsec configurations to directory <dirPath>:

- Main config (config.yaml)
- Profiles config (profiles.yaml)
- Simulation config (simulation.yaml)
- Backup of API credentials (local API and online API)
- List of scenarios, parsers, postoverflows and collections that are up-to-date
- Tainted/local/out-of-date scenarios, parsers, postoverflows and collections
- Acquisition files (acquis.yaml, acquis.d/*.yaml)
*/
func (cli *cliConfig) backup(dirPath string) error {
	var err error

	cfg := cli.cfg()

	if dirPath == "" {
		return errors.New("directory path can't be empty")
	}

	log.Infof("Starting configuration backup")

	/*if parent directory doesn't exist, bail out. create final dir with Mkdir*/
	parentDir := filepath.Dir(dirPath)
	if _, err = os.Stat(parentDir); err != nil {
		return fmt.Errorf("while checking parent directory %s existence: %w", parentDir, err)
	}

	if err = os.Mkdir(dirPath, 0o700); err != nil {
		return fmt.Errorf("while creating %s: %w", dirPath, err)
	}

	if cfg.ConfigPaths.SimulationFilePath != "" {
		backupSimulation := filepath.Join(dirPath, "simulation.yaml")
		if err = CopyFile(cfg.ConfigPaths.SimulationFilePath, backupSimulation); err != nil {
			return fmt.Errorf("failed copy %s to %s: %w", cfg.ConfigPaths.SimulationFilePath, backupSimulation, err)
		}

		log.Infof("Saved simulation to %s", backupSimulation)
	}

	/*
	   - backup AcquisitionFilePath
	   - backup the other files of acquisition directory
	*/
	if cfg.Crowdsec != nil && cfg.Crowdsec.AcquisitionFilePath != "" {
		backupAcquisition := filepath.Join(dirPath, "acquis.yaml")
		if err = CopyFile(cfg.Crowdsec.AcquisitionFilePath, backupAcquisition); err != nil {
			return fmt.Errorf("failed copy %s to %s: %w", cfg.Crowdsec.AcquisitionFilePath, backupAcquisition, err)
		}
	}

	acquisBackupDir := filepath.Join(dirPath, "acquis")
	if err = os.Mkdir(acquisBackupDir, 0o700); err != nil {
		return fmt.Errorf("error while creating %s: %w", acquisBackupDir, err)
	}

	if cfg.Crowdsec != nil && len(cfg.Crowdsec.AcquisitionFiles) > 0 {
		for _, acquisFile := range cfg.Crowdsec.AcquisitionFiles {
			/*if it was the default one, it was already backup'ed*/
			if cfg.Crowdsec.AcquisitionFilePath == acquisFile {
				continue
			}

			targetFname, err := filepath.Abs(filepath.Join(acquisBackupDir, filepath.Base(acquisFile)))
			if err != nil {
				return fmt.Errorf("while saving %s to %s: %w", acquisFile, acquisBackupDir, err)
			}

			if err = CopyFile(acquisFile, targetFname); err != nil {
				return fmt.Errorf("failed copy %s to %s: %w", acquisFile, targetFname, err)
			}

			log.Infof("Saved acquis %s to %s", acquisFile, targetFname)
		}
	}

	if ConfigFilePath != "" {
		backupMain := fmt.Sprintf("%s/config.yaml", dirPath)
		if err = CopyFile(ConfigFilePath, backupMain); err != nil {
			return fmt.Errorf("failed copy %s to %s: %w", ConfigFilePath, backupMain, err)
		}

		log.Infof("Saved default yaml to %s", backupMain)
	}

	if cfg.API != nil && cfg.API.Server != nil && cfg.API.Server.OnlineClient != nil && cfg.API.Server.OnlineClient.CredentialsFilePath != "" {
		backupCAPICreds := fmt.Sprintf("%s/online_api_credentials.yaml", dirPath)
		if err = CopyFile(cfg.API.Server.OnlineClient.CredentialsFilePath, backupCAPICreds); err != nil {
			return fmt.Errorf("failed copy %s to %s: %w", cfg.API.Server.OnlineClient.CredentialsFilePath, backupCAPICreds, err)
		}

		log.Infof("Saved online API credentials to %s", backupCAPICreds)
	}

	if cfg.API != nil && cfg.API.Client != nil && cfg.API.Client.CredentialsFilePath != "" {
		backupLAPICreds := fmt.Sprintf("%s/local_api_credentials.yaml", dirPath)
		if err = CopyFile(cfg.API.Client.CredentialsFilePath, backupLAPICreds); err != nil {
			return fmt.Errorf("failed copy %s to %s: %w", cfg.API.Client.CredentialsFilePath, backupLAPICreds, err)
		}

		log.Infof("Saved local API credentials to %s", backupLAPICreds)
	}

	if cfg.API != nil && cfg.API.Server != nil && cfg.API.Server.ProfilesPath != "" {
		backupProfiles := fmt.Sprintf("%s/profiles.yaml", dirPath)
		if err = CopyFile(cfg.API.Server.ProfilesPath, backupProfiles); err != nil {
			return fmt.Errorf("failed copy %s to %s: %w", cfg.API.Server.ProfilesPath, backupProfiles, err)
		}

		log.Infof("Saved profiles to %s", backupProfiles)
	}

	if err = cli.backupHub(dirPath); err != nil {
		return fmt.Errorf("failed to backup hub config: %w", err)
	}

	return nil
}

func (cli *cliConfig) newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
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
		RunE: func(_ *cobra.Command, args []string) error {
			if err := cli.backup(args[0]); err != nil {
				return fmt.Errorf("failed to backup config: %w", err)
			}

			return nil
		},
	}

	return cmd
}
