package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func (cli *cliConfig) restoreHub(dirPath string) error {
	hub, err := require.Hub(csConfig, require.RemoteHub(csConfig), nil)
	if err != nil {
		return err
	}

	for _, itype := range cwhub.ItemTypes {
		itemDirectory := fmt.Sprintf("%s/%s/", dirPath, itype)
		if _, err = os.Stat(itemDirectory); err != nil {
			log.Infof("no %s in backup", itype)
			continue
		}
		/*restore the upstream items*/
		upstreamListFN := fmt.Sprintf("%s/upstream-%s.json", itemDirectory, itype)

		file, err := os.ReadFile(upstreamListFN)
		if err != nil {
			return fmt.Errorf("error while opening %s: %w", upstreamListFN, err)
		}

		var upstreamList []string

		err = json.Unmarshal(file, &upstreamList)
		if err != nil {
			return fmt.Errorf("error unmarshaling %s: %w", upstreamListFN, err)
		}

		for _, toinstall := range upstreamList {
			item := hub.GetItem(itype, toinstall)
			if item == nil {
				log.Errorf("Item %s/%s not found in hub", itype, toinstall)
				continue
			}

			if err = item.Install(false, false); err != nil {
				log.Errorf("Error while installing %s : %s", toinstall, err)
			}
		}

		/*restore the local and tainted items*/
		files, err := os.ReadDir(itemDirectory)
		if err != nil {
			return fmt.Errorf("failed enumerating files of %s: %w", itemDirectory, err)
		}

		for _, file := range files {
			// this was the upstream data
			if file.Name() == fmt.Sprintf("upstream-%s.json", itype) {
				continue
			}

			if itype == cwhub.PARSERS || itype == cwhub.POSTOVERFLOWS {
				// we expect a stage here
				if !file.IsDir() {
					continue
				}

				stage := file.Name()
				stagedir := fmt.Sprintf("%s/%s/%s/", csConfig.ConfigPaths.ConfigDir, itype, stage)
				log.Debugf("Found stage %s in %s, target directory : %s", stage, itype, stagedir)

				if err = os.MkdirAll(stagedir, os.ModePerm); err != nil {
					return fmt.Errorf("error while creating stage directory %s: %w", stagedir, err)
				}

				// find items
				ifiles, err := os.ReadDir(itemDirectory + "/" + stage + "/")
				if err != nil {
					return fmt.Errorf("failed enumerating files of %s: %w", itemDirectory+"/"+stage, err)
				}

				// finally copy item
				for _, tfile := range ifiles {
					log.Infof("Going to restore local/tainted [%s]", tfile.Name())
					sourceFile := fmt.Sprintf("%s/%s/%s", itemDirectory, stage, tfile.Name())

					destinationFile := fmt.Sprintf("%s%s", stagedir, tfile.Name())
					if err = CopyFile(sourceFile, destinationFile); err != nil {
						return fmt.Errorf("failed copy %s %s to %s: %w", itype, sourceFile, destinationFile, err)
					}

					log.Infof("restored %s to %s", sourceFile, destinationFile)
				}
			} else {
				log.Infof("Going to restore local/tainted [%s]", file.Name())
				sourceFile := fmt.Sprintf("%s/%s", itemDirectory, file.Name())
				destinationFile := fmt.Sprintf("%s/%s/%s", csConfig.ConfigPaths.ConfigDir, itype, file.Name())

				if err = CopyFile(sourceFile, destinationFile); err != nil {
					return fmt.Errorf("failed copy %s %s to %s: %w", itype, sourceFile, destinationFile, err)
				}

				log.Infof("restored %s to %s", sourceFile, destinationFile)
			}
		}
	}

	return nil
}

/*
	Restore crowdsec configurations to directory <dirPath>:

- Main config (config.yaml)
- Profiles config (profiles.yaml)
- Simulation config (simulation.yaml)
- Backup of API credentials (local API and online API)
- List of scenarios, parsers, postoverflows and collections that are up-to-date
- Tainted/local/out-of-date scenarios, parsers, postoverflows and collections
- Acquisition files (acquis.yaml, acquis.d/*.yaml)
*/
func (cli *cliConfig) restore(dirPath string) error {
	var err error

	backupMain := fmt.Sprintf("%s/config.yaml", dirPath)
	if _, err = os.Stat(backupMain); err == nil {
		if csConfig.ConfigPaths != nil && csConfig.ConfigPaths.ConfigDir != "" {
			if err = CopyFile(backupMain, fmt.Sprintf("%s/config.yaml", csConfig.ConfigPaths.ConfigDir)); err != nil {
				return fmt.Errorf("failed copy %s to %s: %w", backupMain, csConfig.ConfigPaths.ConfigDir, err)
			}
		}
	}

	// Now we have config.yaml, we should regenerate config struct to have rights paths etc
	ConfigFilePath = fmt.Sprintf("%s/config.yaml", csConfig.ConfigPaths.ConfigDir)

	log.Debug("Reloading configuration")

	csConfig, _, err = loadConfigFor("config")
	if err != nil {
		return fmt.Errorf("failed to reload configuration: %w", err)
	}

	backupCAPICreds := fmt.Sprintf("%s/online_api_credentials.yaml", dirPath)
	if _, err = os.Stat(backupCAPICreds); err == nil {
		if err = CopyFile(backupCAPICreds, csConfig.API.Server.OnlineClient.CredentialsFilePath); err != nil {
			return fmt.Errorf("failed copy %s to %s: %w", backupCAPICreds, csConfig.API.Server.OnlineClient.CredentialsFilePath, err)
		}
	}

	backupLAPICreds := fmt.Sprintf("%s/local_api_credentials.yaml", dirPath)
	if _, err = os.Stat(backupLAPICreds); err == nil {
		if err = CopyFile(backupLAPICreds, csConfig.API.Client.CredentialsFilePath); err != nil {
			return fmt.Errorf("failed copy %s to %s: %w", backupLAPICreds, csConfig.API.Client.CredentialsFilePath, err)
		}
	}

	backupProfiles := fmt.Sprintf("%s/profiles.yaml", dirPath)
	if _, err = os.Stat(backupProfiles); err == nil {
		if err = CopyFile(backupProfiles, csConfig.API.Server.ProfilesPath); err != nil {
			return fmt.Errorf("failed copy %s to %s: %w", backupProfiles, csConfig.API.Server.ProfilesPath, err)
		}
	}

	backupSimulation := fmt.Sprintf("%s/simulation.yaml", dirPath)
	if _, err = os.Stat(backupSimulation); err == nil {
		if err = CopyFile(backupSimulation, csConfig.ConfigPaths.SimulationFilePath); err != nil {
			return fmt.Errorf("failed copy %s to %s: %w", backupSimulation, csConfig.ConfigPaths.SimulationFilePath, err)
		}
	}

	/*if there is a acquisition dir, restore its content*/
	if csConfig.Crowdsec.AcquisitionDirPath != "" {
		if err = os.MkdirAll(csConfig.Crowdsec.AcquisitionDirPath, 0o700); err != nil {
			return fmt.Errorf("error while creating %s: %w", csConfig.Crowdsec.AcquisitionDirPath, err)
		}
	}

	// if there was a single one
	backupAcquisition := fmt.Sprintf("%s/acquis.yaml", dirPath)
	if _, err = os.Stat(backupAcquisition); err == nil {
		log.Debugf("restoring backup'ed %s", backupAcquisition)

		if err = CopyFile(backupAcquisition, csConfig.Crowdsec.AcquisitionFilePath); err != nil {
			return fmt.Errorf("failed copy %s to %s: %w", backupAcquisition, csConfig.Crowdsec.AcquisitionFilePath, err)
		}
	}

	// if there are files in the acquis backup dir, restore them
	acquisBackupDir := filepath.Join(dirPath, "acquis", "*.yaml")
	if acquisFiles, err := filepath.Glob(acquisBackupDir); err == nil {
		for _, acquisFile := range acquisFiles {
			targetFname, err := filepath.Abs(csConfig.Crowdsec.AcquisitionDirPath + "/" + filepath.Base(acquisFile))
			if err != nil {
				return fmt.Errorf("while saving %s to %s: %w", acquisFile, targetFname, err)
			}

			log.Debugf("restoring %s to %s", acquisFile, targetFname)

			if err = CopyFile(acquisFile, targetFname); err != nil {
				return fmt.Errorf("failed copy %s to %s: %w", acquisFile, targetFname, err)
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
				return fmt.Errorf("while saving %s to %s: %w", acquisFile, acquisBackupDir, err)
			}

			if err = CopyFile(acquisFile, targetFname); err != nil {
				return fmt.Errorf("failed copy %s to %s: %w", acquisFile, targetFname, err)
			}

			log.Infof("Saved acquis %s to %s", acquisFile, targetFname)
		}
	}

	if err = cli.restoreHub(dirPath); err != nil {
		return fmt.Errorf("failed to restore hub config: %w", err)
	}

	return nil
}

func (cli *cliConfig) newRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
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
		RunE: func(_ *cobra.Command, args []string) error {
			dirPath := args[0]

			if err := cli.restore(dirPath); err != nil {
				return fmt.Errorf("failed to restore config from %s: %w", dirPath, err)
			}

			return nil
		},
	}

	return cmd
}
