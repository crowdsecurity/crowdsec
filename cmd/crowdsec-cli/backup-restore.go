package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/cwapi"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/outputs"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

//it's a rip of the cli version, but in silent-mode
func silenceInstallItem(name string, obtype string) (string, error) {
	for _, it := range cwhub.HubIdx[obtype] {
		if it.Name == name {
			if download_only && it.Downloaded && it.UpToDate {
				return fmt.Sprintf("%s is already downloaded and up-to-date", it.Name), nil
			}
			it, err := cwhub.DownloadLatest(it, cwhub.Hubdir, force_install, config.DataFolder)
			if err != nil {
				return "", fmt.Errorf("error while downloading %s : %v", it.Name, err)
			}
			cwhub.HubIdx[obtype][it.Name] = it
			if download_only {
				return fmt.Sprintf("Downloaded %s to %s", it.Name, cwhub.Hubdir+"/"+it.RemotePath), nil
			}
			it, err = cwhub.EnableItem(it, cwhub.Installdir, cwhub.Hubdir)
			if err != nil {
				return "", fmt.Errorf("error while enabled %s : %v", it.Name, err)
			}
			cwhub.HubIdx[obtype][it.Name] = it

			return fmt.Sprintf("Enabled %s", it.Name), nil
		}
	}
	return "", fmt.Errorf("%s not found in hub index", name)
}

/*help to copy the file, ioutil doesn't offer the feature*/

func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}

/*copy the file, ioutile doesn't offer the feature*/
func copyFile(sourceSymLink, destinationFile string) (err error) {

	sourceFile, err := filepath.EvalSymlinks(sourceSymLink)
	if err != nil {
		log.Infof("Not a symlink : %s", err)
		sourceFile = sourceSymLink
	}

	sourceFileStat, err := os.Stat(sourceFile)
	if err != nil {
		return
	}
	if !sourceFileStat.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories,
		// symlinks, devices, etc.)
		return fmt.Errorf("copyFile: non-regular source file %s (%q)", sourceFileStat.Name(), sourceFileStat.Mode().String())
	}
	destinationFileStat, err := os.Stat(destinationFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
	} else {
		if !(destinationFileStat.Mode().IsRegular()) {
			return fmt.Errorf("copyFile: non-regular destination file %s (%q)", destinationFileStat.Name(), destinationFileStat.Mode().String())
		}
		if os.SameFile(sourceFileStat, destinationFileStat) {
			return
		}
	}
	if err = os.Link(sourceFile, destinationFile); err == nil {
		return
	}
	err = copyFileContents(sourceFile, destinationFile)
	return
}

/*given a backup directory, restore configs (parser,collections..) both tainted and untainted.
as well attempts to restore api credentials after verifying the existing ones aren't good
finally restores the acquis.yaml file*/
func restoreFromDirectory(source string) error {
	var err error

	/*restore simulation configuration*/
	backSimul := fmt.Sprintf("%s/simulation.yaml", source)
	if _, err = os.Stat(backSimul); err == nil {
		if err = copyFile(backSimul, config.SimulationCfgPath); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", backSimul, config.SimulationCfgPath, err)
		}
	}

	/*restore scenarios etc.*/
	for _, itype := range cwhub.ItemTypes {
		itemDirectory := fmt.Sprintf("%s/%s/", source, itype)
		if _, err = os.Stat(itemDirectory); err != nil {
			log.Infof("no %s in backup", itype)
			continue
		}
		/*restore the upstream items*/
		upstreamListFN := fmt.Sprintf("%s/upstream-%s.json", itemDirectory, itype)
		file, err := ioutil.ReadFile(upstreamListFN)
		if err != nil {
			return fmt.Errorf("error while opening %s : %s", upstreamListFN, err)
		}
		var upstreamList []string
		err = json.Unmarshal([]byte(file), &upstreamList)
		if err != nil {
			return fmt.Errorf("error unmarshaling %s : %s", upstreamListFN, err)
		}
		for _, toinstall := range upstreamList {
			label, err := silenceInstallItem(toinstall, itype)
			if err != nil {
				log.Errorf("Error while installing %s : %s", toinstall, err)
			} else if label != "" {
				log.Infof("Installed %s : %s", toinstall, label)
			} else {
				log.Printf("Installed %s : ok", toinstall)
			}
		}
		/*restore the local and tainted items*/
		files, err := ioutil.ReadDir(itemDirectory)
		if err != nil {
			return fmt.Errorf("failed enumerating files of %s : %s", itemDirectory, err)
		}
		for _, file := range files {
			//dir are stages, keep track
			if !file.IsDir() {
				continue
			}
			stage := file.Name()
			stagedir := fmt.Sprintf("%s/%s/%s/", config.InstallFolder, itype, stage)
			log.Debugf("Found stage %s in %s, target directory : %s", stage, itype, stagedir)
			if err = os.MkdirAll(stagedir, os.ModePerm); err != nil {
				return fmt.Errorf("error while creating stage directory %s : %s", stagedir, err)
			}
			/*find items*/
			ifiles, err := ioutil.ReadDir(itemDirectory + "/" + stage + "/")
			if err != nil {
				return fmt.Errorf("failed enumerating files of %s : %s", itemDirectory+"/"+stage, err)
			}
			//finaly copy item
			for _, tfile := range ifiles {
				log.Infof("Going to restore local/tainted [%s]", tfile.Name())
				sourceFile := fmt.Sprintf("%s/%s/%s", itemDirectory, stage, tfile.Name())
				destinationFile := fmt.Sprintf("%s%s", stagedir, tfile.Name())
				if err = copyFile(sourceFile, destinationFile); err != nil {
					return fmt.Errorf("failed copy %s %s to %s : %s", itype, sourceFile, destinationFile, err)
				}
				log.Infof("restored %s to %s", sourceFile, destinationFile)
			}
		}
	}
	/*restore api credentials*/
	//check if credentials exists :
	// - if no, restore
	// - if yes, try them :
	//		- if it works, left untouched
	//		- if not, restore
	// -> try login
	if err := restoreAPICreds(source); err != nil {
		return fmt.Errorf("failed to restore api credentials : %s", err)
	}
	/*
		Restore acquis
	*/
	yamlAcquisFile := fmt.Sprintf("%s/acquis.yaml", config.InstallFolder)
	bac := fmt.Sprintf("%s/acquis.yaml", source)
	if err = copyFile(bac, yamlAcquisFile); err != nil {
		return fmt.Errorf("failed copy %s to %s : %s", bac, yamlAcquisFile, err)
	}
	log.Infof("Restore acquis to %s", yamlAcquisFile)

	/* Restore plugins configuration */
	var pluginsConfigFile []string
	walkErr := filepath.Walk(fmt.Sprintf("%s/plugins/backend/", source), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk error : %s", err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("unable to stats file '%s' : %s", path, err)
		}
		mode := fi.Mode()
		if mode.IsRegular() {
			pluginsConfigFile = append(pluginsConfigFile, path)
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("error while listing folder '%s' : %s", fmt.Sprintf("%s/plugins/backend/", source), walkErr)
	}

	if err := os.MkdirAll(outputCTX.Config.BackendFolder, os.ModePerm); err != nil {
		return fmt.Errorf("error while creating backup folder dir %s : %s", outputCTX.Config.BackendFolder, err)
	}

	for _, file := range pluginsConfigFile {
		_, filename := path.Split(file)
		backupFile := fmt.Sprintf("%s/%s", outputCTX.Config.BackendFolder, filename)
		log.Printf("Restoring  '%s' to '%s'", file, backupFile)
		if err := copyFile(file, backupFile); err != nil {
			return fmt.Errorf("error while copying '%s' to '%s' : %s", file, backupFile, err)
		}
	}

	return nil
}

func restoreAPICreds(source string) error {
	var err error

	/*check existing configuration*/
	apiyaml := path.Join(config.InstallFolder, apiConfigFile)

	api := &cwapi.ApiCtx{}
	if err = api.LoadConfig(apiyaml); err != nil {
		return fmt.Errorf("unable to load api config %s : %s", apiyaml, err)
	}
	if api.Creds.User != "" {
		log.Infof("Credentials present in existing configuration, try before override")
		err := api.Signin()
		if err == nil {
			log.Infof("Credentials present allow authentication, don't override !")
			return nil
		} else {
			log.Infof("Credentials aren't valid : %s", err)
		}
	}
	/*existing config isn't good, override it !*/
	ret, err := ioutil.ReadFile(path.Join(source, "api_creds.json"))
	if err != nil {
		return fmt.Errorf("failed to read api creds from save : %s", err)
	}
	if err := json.Unmarshal(ret, &api.Creds); err != nil {
		return fmt.Errorf("failed unmarshaling saved credentials : %s", err)
	}
	api.CfgUser = api.Creds.User
	api.CfgPassword = api.Creds.Password
	/*override the existing yaml file*/
	if err := api.WriteConfig(apiyaml); err != nil {
		return fmt.Errorf("failed writing to %s : %s", apiyaml, err)
	} else {
		log.Infof("Overwritting %s with backup info", apiyaml)
	}

	/*reload to check everything is safe*/
	if err = api.LoadConfig(apiyaml); err != nil {
		return fmt.Errorf("unable to load api config %s : %s", apiyaml, err)
	}

	if err := api.Signin(); err != nil {
		log.Errorf("Failed to authenticate after credentials restaurtion : %v", err)
	} else {
		log.Infof("Successfully auth to API after credentials restauration")
	}

	return nil
}

func backupToDirectory(target string) error {
	var itemDirectory string
	var upstreamParsers []string
	var err error
	if target == "" {
		return fmt.Errorf("target directory can't be empty")
	}
	log.Warningf("Starting configuration backup")
	_, err = os.Stat(target)
	if err == nil {
		return fmt.Errorf("%s already exists", target)
	}
	if err = os.MkdirAll(target, os.ModePerm); err != nil {
		return fmt.Errorf("error while creating %s : %s", target, err)
	}
	/*
		backup configurations :
			- parers, scenarios, collections, postoverflows
			- simulation configuration
	*/
	if config.SimulationCfgPath != "" {
		backSimul := fmt.Sprintf("%s/simulation.yaml", target)
		if err = copyFile(config.SimulationCfgPath, backSimul); err != nil {
			return fmt.Errorf("failed copy %s to %s : %s", config.SimulationCfgPath, backSimul, err)
		}
	}

	for _, itemType := range cwhub.ItemTypes {
		clog := log.WithFields(log.Fields{
			"type": itemType,
		})
		if _, ok := cwhub.HubIdx[itemType]; ok {
			itemDirectory = fmt.Sprintf("%s/%s/", target, itemType)
			if err := os.MkdirAll(itemDirectory, os.ModePerm); err != nil {
				return fmt.Errorf("error while creating %s : %s", itemDirectory, err)
			}
			upstreamParsers = []string{}
			stage := ""
			for k, v := range cwhub.HubIdx[itemType] {
				clog = clog.WithFields(log.Fields{
					"file": v.Name,
				})
				if !v.Installed { //only backup installed ones
					clog.Debugf("[%s] : not installed", k)
					continue
				}

				//for the local/tainted ones, we backup the full file
				if v.Tainted || v.Local || !v.UpToDate {
					//we need to backup stages for parsers
					if itemType == cwhub.PARSERS || itemType == cwhub.PARSERS_OVFLW {
						tmp := strings.Split(v.LocalPath, "/")
						stage = "/" + tmp[len(tmp)-2] + "/"
						fstagedir := fmt.Sprintf("%s%s", itemDirectory, stage)
						if err := os.MkdirAll(fstagedir, os.ModePerm); err != nil {
							return fmt.Errorf("error while creating stage dir %s : %s", fstagedir, err)
						}
					}
					clog.Debugf("[%s] : backuping file (tainted:%t local:%t up-to-date:%t)", k, v.Tainted, v.Local, v.UpToDate)
					tfile := fmt.Sprintf("%s%s%s", itemDirectory, stage, v.FileName)
					//clog.Infof("item : %s", spew.Sdump(v))
					if err = copyFile(v.LocalPath, tfile); err != nil {
						return fmt.Errorf("failed copy %s %s to %s : %s", itemType, v.LocalPath, tfile, err)
					}
					clog.Infof("local/tainted saved %s to %s", v.LocalPath, tfile)
					continue
				}
				clog.Debugf("[%s] : from hub, just backup name (up-to-date:%t)", k, v.UpToDate)
				clog.Infof("saving, version:%s, up-to-date:%t", v.Version, v.UpToDate)
				upstreamParsers = append(upstreamParsers, v.Name)
			}
			//write the upstream items
			upstreamParsersFname := fmt.Sprintf("%s/upstream-%s.json", itemDirectory, itemType)
			upstreamParsersContent, err := json.MarshalIndent(upstreamParsers, "", " ")
			if err != nil {
				return fmt.Errorf("failed marshaling upstream parsers : %s", err)
			}
			err = ioutil.WriteFile(upstreamParsersFname, upstreamParsersContent, 0644)
			if err != nil {
				return fmt.Errorf("unable to write to %s %s : %s", itemType, upstreamParsersFname, err)
			}
			clog.Infof("Wrote %d entries for %s to %s", len(upstreamParsers), itemType, upstreamParsersFname)

		} else {
			clog.Infof("No %s to backup.", itemType)
		}
	}
	/*
		Backup acquis
	*/
	yamlAcquisFile := fmt.Sprintf("%s/acquis.yaml", config.InstallFolder)
	bac := fmt.Sprintf("%s/acquis.yaml", target)
	if err = copyFile(yamlAcquisFile, bac); err != nil {
		return fmt.Errorf("failed copy %s to %s : %s", yamlAcquisFile, bac, err)
	}
	log.Infof("Saved acquis to %s", bac)
	/*
		Backup default.yaml
	*/
	defyaml := fmt.Sprintf("%s/default.yaml", config.InstallFolder)
	bac = fmt.Sprintf("%s/default.yaml", target)
	if err = copyFile(defyaml, bac); err != nil {
		return fmt.Errorf("failed copy %s to %s : %s", yamlAcquisFile, bac, err)
	}
	log.Infof("Saved default yaml to %s", bac)
	/*
		Backup API info
	*/
	if outputCTX == nil {
		log.Fatalf("no API output context, won't save api credentials")
	}
	outputCTX.API = &cwapi.ApiCtx{}
	if err = outputCTX.API.LoadConfig(path.Join(config.InstallFolder, apiConfigFile)); err != nil {
		return fmt.Errorf("unable to load api config %s : %s", path.Join(config.InstallFolder, apiConfigFile), err)
	}
	credsYaml, err := json.Marshal(&outputCTX.API.Creds)
	if err != nil {
		log.Fatalf("can't marshal credentials : %v", err)
	}
	apiCredsDumped := fmt.Sprintf("%s/api_creds.json", target)
	err = ioutil.WriteFile(apiCredsDumped, credsYaml, 0600)
	if err != nil {
		return fmt.Errorf("unable to write credentials to %s : %s", apiCredsDumped, err)
	}
	log.Infof("Saved configuration to %s", target)

	/* Backup plugins configuration */
	var pluginsConfigFile []string
	walkErr := filepath.Walk(outputCTX.Config.BackendFolder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk error : %s", err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("unable to stats file '%s' : %s", path, err)
		}
		mode := fi.Mode()
		if mode.IsRegular() {
			pluginsConfigFile = append(pluginsConfigFile, path)
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("error while listing folder '%s' : %s", outputCTX.Config.BackendFolder, walkErr)
	}

	targetDir := fmt.Sprintf("%s/plugins/backend/", target)
	if err := os.MkdirAll(targetDir, os.ModePerm); err != nil {
		return fmt.Errorf("error while creating backup folder dir %s : %s", targetDir, err)
	}

	for _, file := range pluginsConfigFile {
		_, filename := path.Split(file)
		backupFile := fmt.Sprintf("%s/plugins/backend/%s", target, filename)
		if err := copyFile(file, backupFile); err != nil {
			return fmt.Errorf("unable to copy file '%s' to '%s' : %s", file, backupFile, err)
		}
	}

	return nil
}

func NewBackupCmd() *cobra.Command {
	var cmdBackup = &cobra.Command{
		Use:   "backup [save|restore] <directory>",
		Short: "Backup or restore configuration (api, parsers, scenarios etc.) to/from directory",
		Long:  `This command is here to help you save and/or restore crowdsec configurations to simple replication`,
		Example: `cscli backup save ./my-backup
cscli backup restore ./my-backup`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !config.configured {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}
			return nil
		},
	}

	var cmdBackupSave = &cobra.Command{
		Use:   "save <directory>",
		Short: "Backup configuration (api, parsers, scenarios etc.) to directory",
		Long: `backup command will try to save all relevant informations to crowdsec config, including :

- List of scenarios, parsers, postoverflows and collections that are up-to-date

- Actual backup of tainted/local/out-of-date scenarios, parsers, postoverflows and collections

- Backup of API credentials

- Backup of acquisition configuration
		
		`,
		Example: `cscli backup save ./my-backup`,
		Args:    cobra.ExactArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !config.configured {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			var err error

			outputConfig := outputs.OutputFactory{
				BackendFolder: config.BackendPluginFolder,
				Flush:         false,
			}
			outputCTX, err = outputs.NewOutput(&outputConfig)
			if err != nil {
				log.Fatalf("Failed to load output plugins : %v", err)
			}
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if err := backupToDirectory(args[0]); err != nil {
				log.Fatalf("Failed backuping to %s : %s", args[0], err)
			}
		},
	}
	cmdBackup.AddCommand(cmdBackupSave)

	var cmdBackupRestore = &cobra.Command{
		Use:   "restore <directory>",
		Short: "Restore configuration (api, parsers, scenarios etc.) from directory",
		Long: `restore command will try to restore all saved information from <directory> to yor local setup, including :

- Installation of up-to-date scenarios/parsers/... via cscli

- Restauration of tainted/local/out-of-date scenarios/parsers/... file

- Restauration of API credentials (if the existing ones aren't working)

- Restauration of acqusition configuration
`,
		Example: `cscli backup restore ./my-backup`,
		Args:    cobra.ExactArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !config.configured {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			var err error

			outputConfig := outputs.OutputFactory{
				BackendFolder: config.BackendPluginFolder,
				Flush:         false,
			}
			outputCTX, err = outputs.NewOutput(&outputConfig)
			if err != nil {
				log.Fatalf("Failed to load output plugins : %v", err)
			}

			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			if err := restoreFromDirectory(args[0]); err != nil {
				log.Fatalf("failed restoring from %s : %s", args[0], err)
			}
		},
	}
	cmdBackup.AddCommand(cmdBackupRestore)

	return cmdBackup
}
