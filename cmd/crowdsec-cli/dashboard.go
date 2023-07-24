package main

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/AlecAivazis/survey/v2"
	"github.com/pbnjay/memory"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/metabase"
)

var (
	metabaseUser         = "crowdsec@crowdsec.net"
	metabasePassword     string
	metabaseDbPath       string
	metabaseConfigPath   string
	metabaseConfigFolder = "metabase/"
	metabaseConfigFile   = "metabase.yaml"
	metabaseImage        = "metabase/metabase:v0.46.6.1"
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
				log.Fatal(err)
			}
			if err := csConfig.LoadDBConfig(); err != nil {
				log.Errorf("This command requires direct database access (must be run on the local API machine)")
				log.Fatal(err)
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

	cmdDashboard.AddCommand(NewDashboardSetupCmd())
	cmdDashboard.AddCommand(NewDashboardStartCmd())
	cmdDashboard.AddCommand(NewDashboardStopCmd())
	cmdDashboard.AddCommand(NewDashboardShowPasswordCmd())
	cmdDashboard.AddCommand(NewDashboardRemoveCmd())

	return cmdDashboard
}

func NewDashboardSetupCmd() *cobra.Command {
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
		RunE: func(cmd *cobra.Command, args []string) error {
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
			if err := checkSystemMemory(&forceYes); err != nil {
				return err
			}
			if err := warnIfNotLoopback(metabaseListenAddress, &forceYes); err != nil {
				return err
			}
			dockerGroup, err := checkGroups(&forceYes)
			if err != nil {
				return err
			}
			mb, err := metabase.SetupMetabase(csConfig.API.Server.DbConfig, metabaseListenAddress, metabaseListenPort, metabaseUser, metabasePassword, metabaseDbPath, dockerGroup.Gid, metabaseContainerID, metabaseImage)
			if err != nil {
				return err
			}
			if err := mb.DumpConfig(metabaseConfigPath); err != nil {
				return err
			}

			log.Infof("Metabase is ready")
			fmt.Println()
			fmt.Printf("\tURL       : '%s'\n", mb.Config.ListenURL)
			fmt.Printf("\tusername  : '%s'\n", mb.Config.Username)
			fmt.Printf("\tpassword  : '%s'\n", mb.Config.Password)
			return nil
		},
	}
	cmdDashSetup.Flags().BoolVarP(&force, "force", "f", false, "Force setup : override existing files")
	cmdDashSetup.Flags().StringVarP(&metabaseDbPath, "dir", "d", "", "Shared directory with metabase container")
	cmdDashSetup.Flags().StringVarP(&metabaseListenAddress, "listen", "l", metabaseListenAddress, "Listen address of container")
	cmdDashSetup.Flags().StringVarP(&metabaseImage, "version", "v", metabaseImage, "Metabase image to use")
	cmdDashSetup.Flags().StringVarP(&metabaseListenPort, "port", "p", metabaseListenPort, "Listen port of container")
	cmdDashSetup.Flags().BoolVarP(&forceYes, "yes", "y", false, "force  yes")
	//cmdDashSetup.Flags().StringVarP(&metabaseUser, "user", "u", "crowdsec@crowdsec.net", "metabase user")
	cmdDashSetup.Flags().StringVar(&metabasePassword, "password", "", "metabase password")

	return cmdDashSetup
}

func NewDashboardStartCmd() *cobra.Command {
	var cmdDashStart = &cobra.Command{
		Use:               "start",
		Short:             "Start the metabase container.",
		Long:              `Stats the metabase container using docker.`,
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			mb, err := metabase.NewMetabase(metabaseConfigPath, metabaseContainerID)
			if err != nil {
				return err
			}
			if err := warnIfNotLoopback(mb.Config.ListenAddr, &forceYes); err != nil {
				return err
			}
			if err := mb.Container.Start(); err != nil {
				return fmt.Errorf("failed to start metabase container : %s", err)
			}
			log.Infof("Started metabase")
			log.Infof("url : http://%s:%s", mb.Config.ListenAddr, mb.Config.ListenPort)
			return nil
		},
	}
	return cmdDashStart
}

func NewDashboardStopCmd() *cobra.Command {
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
	return cmdDashStop
}

func NewDashboardShowPasswordCmd() *cobra.Command {
	var cmdDashShowPassword = &cobra.Command{Use: "show-password",
		Short:             "displays password of metabase.",
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			m := metabase.Metabase{}
			if err := m.LoadConfig(metabaseConfigPath); err != nil {
				log.Fatal(err)
			}
			log.Printf("'%s'", m.Config.Password)
		},
	}
	return cmdDashShowPassword
}

func NewDashboardRemoveCmd() *cobra.Command {
	var force bool

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
					m := metabase.Metabase{}
					if err := m.LoadConfig(metabaseConfigPath); err != nil {
						log.Fatal(err)
					}
					if err := metabase.RemoveImageContainer(m.Config.Image); err != nil {
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

	return cmdDashRemove
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

func checkSystemMemory(forceYes *bool) error {
	totMem := memory.TotalMemory()
	var answer bool
	if totMem >= uint64(math.Pow(2, 30)) {
		return nil
	}
	if !*forceYes {
		prompt := &survey.Confirm{
			Message: "Metabase requires 1-2GB of RAM, your system is below this requirement continue ?",
			Default: true,
		}
		if err := survey.AskOne(prompt, &answer); err != nil {
			return fmt.Errorf("unable to ask about RAM check: %s", err)
		}
		if !answer {
			return fmt.Errorf("user aborted")
		}
		return nil
	}
	log.Warn("Metabase requires 1-2GB of RAM, your system is below this requirement")
	return nil
}

func warnIfNotLoopback(addr string, forceYes *bool) error {
	if addr == "127.0.0.1" || addr == "[::1]" {
		return nil
	}
	log.Warnf("You are potentially exposing your metabase port to the internet (addr: %s), please consider using a reverse proxy", addr)
	log.Warn("CrowdSec takes no responsibility for security of your metabase instance.")
	if !*forceYes {
		var answer bool
		prompt := &survey.Confirm{
			Message: "Do you want to continue ?",
			Default: true,
		}
		if err := survey.AskOne(prompt, &answer); err != nil {
			return fmt.Errorf("unable to ask to question: %s", err)
		}
		if !answer {
			return fmt.Errorf("user aborted")
		}
	}
	return nil
}

func checkGroups(force *bool) (*user.Group, error) {
	var answer bool
	var err error
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
			return dockerGroup, fmt.Errorf("unable to ask to force: %s", err)
		}
	}
	if !answer && !forceYes && !groupExist {
		return dockerGroup, fmt.Errorf("unable to continue without creating '%s' group", crowdsecGroup)
	}
	if !groupExist {
		groupAddCmd, err := exec.LookPath("groupadd")
		if err != nil {
			return dockerGroup, fmt.Errorf("unable to find 'groupadd' command, can't continue")
		}

		groupAdd := &exec.Cmd{Path: groupAddCmd, Args: []string{groupAddCmd, crowdsecGroup}}
		if err := groupAdd.Run(); err != nil {
			return dockerGroup, fmt.Errorf("unable to add group '%s': %s", dockerGroup, err)
		}
		dockerGroup, err = user.LookupGroup(crowdsecGroup)
		if err != nil {
			return dockerGroup, fmt.Errorf("unable to lookup '%s' group: %+v", dockerGroup, err)
		}
	}
	intID, err := strconv.Atoi(dockerGroup.Gid)
	if err != nil {
		return dockerGroup, fmt.Errorf("unable to convert group ID to int: %s", err)
	}
	if err := os.Chown(csConfig.DbConfig.DbPath, 0, intID); err != nil {
		return dockerGroup, fmt.Errorf("unable to chown sqlite db file '%s': %s", csConfig.DbConfig.DbPath, err)
	}
	return dockerGroup, nil
}
