package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/AlecAivazis/survey/v2"
	"github.com/crowdsecurity/crowdsec/pkg/metabase"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	metabaseUser         = "crowdsec@crowdsec.net"
	metabasePassword     string
	metabaseDbPath       string
	metabaseConfigPath   string
	metabaseConfigFolder = "metabase/"
	metabaseConfigFile   = "metabase.yaml"
	/**/
	metabaseListenAddress = "127.0.0.1"
	metabaseListenPort    = "3000"
	metabaseContainerID   = "crowdsec-metabase"
	crowdsecGroup         = "crowdsec"

	forceYes bool

	/*informations needed to setup a random password on user's behalf*/
)

func NewDashboardCmd() *cobra.Command {
	/* ---- UPDATE COMMAND */
	var cmdDashboard = &cobra.Command{
		Use:   "dashboard [command]",
		Short: "Manage your metabase dashboard container [requires local API]",
		Long: `Install/Start/Stop/Remove a metabase container exposing dashboard and metrics.
Note: This command requires database direct access, so is intended to be run on Local API/master.
		`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		Example: `
cscli dashboard setup
cscli dashboard start
cscli dashboard stop
cscli dashboard remove
`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if err := metabase.TestAvailability(); err != nil {
				log.Fatalf("%s", err)
			}

			if err := csConfig.LoadAPIServer(); err != nil || csConfig.DisableAPI {
				log.Fatal("Local API is disabled, please run this command on the local API machine")
			}

			metabaseConfigFolderPath := filepath.Join(csConfig.ConfigPaths.ConfigDir, metabaseConfigFolder)
			metabaseConfigPath = filepath.Join(metabaseConfigFolderPath, metabaseConfigFile)
			if err := os.MkdirAll(metabaseConfigFolderPath, os.ModePerm); err != nil {
				log.Fatalf(err.Error())
			}
			if err := csConfig.LoadDBConfig(); err != nil {
				log.Errorf("This command requires direct database access (must be run on the local API machine)")
				log.Fatalf(err.Error())
			}

			/*
				Old container name was "/crowdsec-metabase" but podman doesn't
				allow '/' in container name. We do this check to not break
				existing dashboard setup.
			*/
			if !metabase.IsContainerExist(metabaseContainerID) {
				oldContainerID := fmt.Sprintf("/%s", metabaseContainerID)
				if metabase.IsContainerExist(oldContainerID) {
					metabaseContainerID = oldContainerID
				}
			}
		},
	}

	var force bool
	var cmdDashSetup = &cobra.Command{
		Use:               "setup",
		Short:             "Setup a metabase container.",
		Long:              `Perform a metabase docker setup, download standard dashboards, create a fresh user and start the container`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Example: `
cscli dashboard setup
cscli dashboard setup --listen 0.0.0.0
cscli dashboard setup -l 0.0.0.0 -p 443 --password <password>
 `,
		Run: func(cmd *cobra.Command, args []string) {
			if metabaseDbPath == "" {
				metabaseDbPath = csConfig.ConfigPaths.DataDir
			}

			if metabasePassword == "" {
				isValid := passwordIsValid(metabasePassword)
				for !isValid {
					metabasePassword = generatePassword(16)
					isValid = passwordIsValid(metabasePassword)
				}
			}
			var answer bool
			groupExist := false
			dockerGroup, err := user.LookupGroup(crowdsecGroup)
			if err == nil {
				groupExist = true
			}
			if !forceYes && !groupExist {
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("For metabase docker to be able to access SQLite file we need to add a new group called '%s' to the system, is it ok for you ?", crowdsecGroup),
					Default: true,
				}
				if err := survey.AskOne(prompt, &answer); err != nil {
					log.Fatalf("unable to ask to force: %s", err)
				}
			}
			if !answer && !forceYes && !groupExist {
				log.Fatalf("unable to continue without creating '%s' group", crowdsecGroup)
			}
			if !groupExist {
				groupAddCmd, err := exec.LookPath("groupadd")
				if err != nil {
					log.Fatalf("unable to find 'groupadd' command, can't continue")
				}

				groupAdd := &exec.Cmd{Path: groupAddCmd, Args: []string{groupAddCmd, crowdsecGroup}}
				if err := groupAdd.Run(); err != nil {
					log.Fatalf("unable to add group '%s': %s", dockerGroup, err)
				}
				dockerGroup, err = user.LookupGroup(crowdsecGroup)
				if err != nil {
					log.Fatalf("unable to lookup '%s' group: %+v", dockerGroup, err)
				}
			}
			intID, err := strconv.Atoi(dockerGroup.Gid)
			if err != nil {
				log.Fatalf("unable to convert group ID to int: %s", err)
			}
			if err := os.Chown(csConfig.DbConfig.DbPath, 0, intID); err != nil {
				log.Fatalf("unable to chown sqlite db file '%s': %s", csConfig.DbConfig.DbPath, err)
			}

			mb, err := metabase.SetupMetabase(csConfig.API.Server.DbConfig, metabaseListenAddress, metabaseListenPort, metabaseUser, metabasePassword, metabaseDbPath, dockerGroup.Gid, metabaseContainerID)
			if err != nil {
				log.Fatalf(err.Error())
			}

			if err := mb.DumpConfig(metabaseConfigPath); err != nil {
				log.Fatalf(err.Error())
			}

			log.Infof("Metabase is ready")
			fmt.Println()
			fmt.Printf("\tURL       : '%s'\n", mb.Config.ListenURL)
			fmt.Printf("\tusername  : '%s'\n", mb.Config.Username)
			fmt.Printf("\tpassword  : '%s'\n", mb.Config.Password)
		},
	}
	cmdDashSetup.Flags().BoolVarP(&force, "force", "f", false, "Force setup : override existing files.")
	cmdDashSetup.Flags().StringVarP(&metabaseDbPath, "dir", "d", "", "Shared directory with metabase container.")
	cmdDashSetup.Flags().StringVarP(&metabaseListenAddress, "listen", "l", metabaseListenAddress, "Listen address of container")
	cmdDashSetup.Flags().StringVarP(&metabaseListenPort, "port", "p", metabaseListenPort, "Listen port of container")
	cmdDashSetup.Flags().BoolVarP(&forceYes, "yes", "y", false, "force  yes")
	//cmdDashSetup.Flags().StringVarP(&metabaseUser, "user", "u", "crowdsec@crowdsec.net", "metabase user")
	cmdDashSetup.Flags().StringVar(&metabasePassword, "password", "", "metabase password")

	cmdDashboard.AddCommand(cmdDashSetup)

	var cmdDashStart = &cobra.Command{
		Use:               "start",
		Short:             "Start the metabase container.",
		Long:              `Stats the metabase container using docker.`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			mb, err := metabase.NewMetabase(metabaseConfigPath, metabaseContainerID)
			if err != nil {
				log.Fatalf(err.Error())
			}
			if err := mb.Container.Start(); err != nil {
				log.Fatalf("Failed to start metabase container : %s", err)
			}
			log.Infof("Started metabase")
			log.Infof("url : http://%s:%s", metabaseListenAddress, metabaseListenPort)
		},
	}
	cmdDashboard.AddCommand(cmdDashStart)

	var cmdDashStop = &cobra.Command{
		Use:               "stop",
		Short:             "Stops the metabase container.",
		Long:              `Stops the metabase container using docker.`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := metabase.StopContainer(metabaseContainerID); err != nil {
				log.Fatalf("unable to stop container '%s': %s", metabaseContainerID, err)
			}
		},
	}
	cmdDashboard.AddCommand(cmdDashStop)

	var cmdDashRemove = &cobra.Command{
		Use:               "remove",
		Short:             "removes the metabase container.",
		Long:              `removes the metabase container using docker.`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Example: `
cscli dashboard remove
cscli dashboard remove --force
 `,
		Run: func(cmd *cobra.Command, args []string) {
			answer := true
			if !forceYes {
				prompt := &survey.Confirm{
					Message: "Do you really want to remove crowdsec dashboard? (all your changes will be lost)",
					Default: true,
				}
				if err := survey.AskOne(prompt, &answer); err != nil {
					log.Fatalf("unable to ask to force: %s", err)
				}
			}
			if answer {
				if metabase.IsContainerExist(metabaseContainerID) {
					log.Debugf("Stopping container %s", metabaseContainerID)
					if err := metabase.StopContainer(metabaseContainerID); err != nil {
						log.Warningf("unable to stop container '%s': %s", metabaseContainerID, err)
					}
					dockerGroup, err := user.LookupGroup(crowdsecGroup)
					if err == nil { // if group exist, remove it
						groupDelCmd, err := exec.LookPath("groupdel")
						if err != nil {
							log.Fatalf("unable to find 'groupdel' command, can't continue")
						}

						groupDel := &exec.Cmd{Path: groupDelCmd, Args: []string{groupDelCmd, crowdsecGroup}}
						if err := groupDel.Run(); err != nil {
							log.Errorf("unable to delete group '%s': %s", dockerGroup, err)
						}
					}
					log.Debugf("Removing container %s", metabaseContainerID)
					if err := metabase.RemoveContainer(metabaseContainerID); err != nil {
						log.Warningf("unable to remove container '%s': %s", metabaseContainerID, err)
					}
					log.Infof("container %s stopped & removed", metabaseContainerID)
				}
				log.Debugf("Removing metabase db %s", csConfig.ConfigPaths.DataDir)
				if err := metabase.RemoveDatabase(csConfig.ConfigPaths.DataDir); err != nil {
					log.Warningf("failed to remove metabase internal db : %s", err)
				}
				if force {
					if err := metabase.RemoveImageContainer(); err != nil {
						if !strings.Contains(err.Error(), "No such image") {
							log.Fatalf("removing docker image: %s", err)
						}
					}
				}
			}
		},
	}
	cmdDashRemove.Flags().BoolVarP(&force, "force", "f", false, "Remove also the metabase image")
	cmdDashRemove.Flags().BoolVarP(&forceYes, "yes", "y", false, "force  yes")
	cmdDashboard.AddCommand(cmdDashRemove)

	return cmdDashboard
}

func passwordIsValid(password string) bool {
	hasDigit := false
	for _, j := range password {
		if unicode.IsDigit(j) {
			hasDigit = true
			break
		}
	}

	if !hasDigit || len(password) < 6 {
		return false
	}
	return true

}
