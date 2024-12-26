//go:build linux

package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/AlecAivazis/survey/v2"
	"github.com/pbnjay/memory"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/idgen"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/require"
	"github.com/crowdsecurity/crowdsec/pkg/metabase"
)

var (
	metabaseUser         = "crowdsec@crowdsec.net"
	metabasePassword     string
	metabaseDBPath       string
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

	// information needed to set up a random password on user's behalf
)

type cliDashboard struct {
	cfg configGetter
}

func NewCLIDashboard(cfg configGetter) *cliDashboard {
	return &cliDashboard{
		cfg: cfg,
	}
}

func (cli *cliDashboard) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
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
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if version.System == "docker" {
				return errors.New("cscli dashboard is not supported whilst running CrowdSec within a container please see: https://github.com/crowdsecurity/example-docker-compose/tree/main/basic")
			}

			cfg := cli.cfg()
			if err := require.LAPI(cfg); err != nil {
				return err
			}

			if err := metabase.TestAvailability(); err != nil {
				return err
			}

			metabaseConfigFolderPath := filepath.Join(cfg.ConfigPaths.ConfigDir, metabaseConfigFolder)
			metabaseConfigPath = filepath.Join(metabaseConfigFolderPath, metabaseConfigFile)
			if err := os.MkdirAll(metabaseConfigFolderPath, os.ModePerm); err != nil {
				return err
			}

			if err := require.DB(cfg); err != nil {
				return err
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

			log.Warn("cscli dashboard will be deprecated in version 1.7.0, read more at https://docs.crowdsec.net/blog/cscli_dashboard_deprecation/")

			return nil
		},
	}

	cmd.AddCommand(cli.newSetupCmd())
	cmd.AddCommand(cli.newStartCmd())
	cmd.AddCommand(cli.newStopCmd())
	cmd.AddCommand(cli.newShowPasswordCmd())
	cmd.AddCommand(cli.newRemoveCmd())

	return cmd
}

func (cli *cliDashboard) newSetupCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:               "setup",
		Short:             "Setup a metabase container.",
		Long:              `Perform a metabase docker setup, download standard dashboards, create a fresh user and start the container`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		Example: `
cscli dashboard setup
cscli dashboard setup --listen 0.0.0.0
cscli dashboard setup -l 0.0.0.0 -p 443 --password <password>
 `,
		RunE: func(_ *cobra.Command, _ []string) error {
			if metabaseDBPath == "" {
				metabaseDBPath = cli.cfg().ConfigPaths.DataDir
			}

			if metabasePassword == "" {
				isValid := passwordIsValid(metabasePassword)
				for !isValid {
					var err error
					metabasePassword, err = idgen.GeneratePassword(16)
					if err != nil {
						return err
					}
					isValid = passwordIsValid(metabasePassword)
				}
			}
			if err := checkSystemMemory(&forceYes); err != nil {
				return err
			}
			warnIfNotLoopback(metabaseListenAddress)
			if err := disclaimer(&forceYes); err != nil {
				return err
			}
			dockerGroup, err := checkGroups(&forceYes)
			if err != nil {
				return err
			}
			if err = cli.chownDatabase(dockerGroup.Gid); err != nil {
				return err
			}
			mb, err := metabase.SetupMetabase(cli.cfg().API.Server.DbConfig, metabaseListenAddress, metabaseListenPort, metabaseUser, metabasePassword, metabaseDBPath, dockerGroup.Gid, metabaseContainerID, metabaseImage)
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

	flags := cmd.Flags()
	flags.BoolVarP(&force, "force", "f", false, "Force setup : override existing files")
	flags.StringVarP(&metabaseDBPath, "dir", "d", "", "Shared directory with metabase container")
	flags.StringVarP(&metabaseListenAddress, "listen", "l", metabaseListenAddress, "Listen address of container")
	flags.StringVar(&metabaseImage, "metabase-image", metabaseImage, "Metabase image to use")
	flags.StringVarP(&metabaseListenPort, "port", "p", metabaseListenPort, "Listen port of container")
	flags.BoolVarP(&forceYes, "yes", "y", false, "force  yes")
	// flags.StringVarP(&metabaseUser, "user", "u", "crowdsec@crowdsec.net", "metabase user")
	flags.StringVar(&metabasePassword, "password", "", "metabase password")

	return cmd
}

func (cli *cliDashboard) newStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "start",
		Short:             "Start the metabase container.",
		Long:              `Stats the metabase container using docker.`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			mb, err := metabase.NewMetabase(metabaseConfigPath, metabaseContainerID)
			if err != nil {
				return err
			}
			warnIfNotLoopback(mb.Config.ListenAddr)
			if err := disclaimer(&forceYes); err != nil {
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

	cmd.Flags().BoolVarP(&forceYes, "yes", "y", false, "force  yes")

	return cmd
}

func (cli *cliDashboard) newStopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "stop",
		Short:             "Stops the metabase container.",
		Long:              `Stops the metabase container using docker.`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := metabase.StopContainer(metabaseContainerID); err != nil {
				return fmt.Errorf("unable to stop container '%s': %s", metabaseContainerID, err)
			}
			return nil
		},
	}

	return cmd
}

func (cli *cliDashboard) newShowPasswordCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "show-password",
		Short:             "displays password of metabase.",
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			m := metabase.Metabase{}
			if err := m.LoadConfig(metabaseConfigPath); err != nil {
				return err
			}
			log.Printf("'%s'", m.Config.Password)

			return nil
		},
	}

	return cmd
}

func (cli *cliDashboard) newRemoveCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:               "remove",
		Short:             "removes the metabase container.",
		Long:              `removes the metabase container using docker.`,
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		Example: `
cscli dashboard remove
cscli dashboard remove --force
 `,
		RunE: func(_ *cobra.Command, _ []string) error {
			if !forceYes {
				var answer bool
				prompt := &survey.Confirm{
					Message: "Do you really want to remove crowdsec dashboard? (all your changes will be lost)",
					Default: true,
				}
				if err := survey.AskOne(prompt, &answer); err != nil {
					return fmt.Errorf("unable to ask to force: %s", err)
				}
				if !answer {
					return errors.New("user stated no to continue")
				}
			}
			if metabase.IsContainerExist(metabaseContainerID) {
				log.Debugf("Stopping container %s", metabaseContainerID)
				if err := metabase.StopContainer(metabaseContainerID); err != nil {
					log.Warningf("unable to stop container '%s': %s", metabaseContainerID, err)
				}
				dockerGroup, err := user.LookupGroup(crowdsecGroup)
				if err == nil { // if group exist, remove it
					groupDelCmd, err := exec.LookPath("groupdel")
					if err != nil {
						return errors.New("unable to find 'groupdel' command, can't continue")
					}

					groupDel := &exec.Cmd{Path: groupDelCmd, Args: []string{groupDelCmd, crowdsecGroup}}
					if err := groupDel.Run(); err != nil {
						log.Warnf("unable to delete group '%s': %s", dockerGroup, err)
					}
				}
				log.Debugf("Removing container %s", metabaseContainerID)
				if err := metabase.RemoveContainer(metabaseContainerID); err != nil {
					log.Warnf("unable to remove container '%s': %s", metabaseContainerID, err)
				}
				log.Infof("container %s stopped & removed", metabaseContainerID)
			}
			log.Debugf("Removing metabase db %s", cli.cfg().ConfigPaths.DataDir)
			if err := metabase.RemoveDatabase(cli.cfg().ConfigPaths.DataDir); err != nil {
				log.Warnf("failed to remove metabase internal db : %s", err)
			}
			if force {
				m := metabase.Metabase{}
				if err := m.LoadConfig(metabaseConfigPath); err != nil {
					return err
				}
				if err := metabase.RemoveImageContainer(m.Config.Image); err != nil {
					if !strings.Contains(err.Error(), "No such image") {
						return fmt.Errorf("removing docker image: %s", err)
					}
				}
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&force, "force", "f", false, "Remove also the metabase image")
	flags.BoolVarP(&forceYes, "yes", "y", false, "force  yes")

	return cmd
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
	if totMem >= uint64(math.Pow(2, 30)) {
		return nil
	}

	if !*forceYes {
		var answer bool

		prompt := &survey.Confirm{
			Message: "Metabase requires 1-2GB of RAM, your system is below this requirement continue ?",
			Default: true,
		}
		if err := survey.AskOne(prompt, &answer); err != nil {
			return fmt.Errorf("unable to ask about RAM check: %s", err)
		}

		if !answer {
			return errors.New("user stated no to continue")
		}

		return nil
	}

	log.Warn("Metabase requires 1-2GB of RAM, your system is below this requirement")

	return nil
}

func warnIfNotLoopback(addr string) {
	if addr == "127.0.0.1" || addr == "::1" {
		return
	}

	log.Warnf("You are potentially exposing your metabase port to the internet (addr: %s), please consider using a reverse proxy", addr)
}

func disclaimer(forceYes *bool) error {
	if !*forceYes {
		var answer bool

		prompt := &survey.Confirm{
			Message: "CrowdSec takes no responsibility for the security of your metabase instance. Do you accept these responsibilities ?",
			Default: true,
		}

		if err := survey.AskOne(prompt, &answer); err != nil {
			return fmt.Errorf("unable to ask to question: %s", err)
		}

		if !answer {
			return errors.New("user stated no to responsibilities")
		}

		return nil
	}

	log.Warn("CrowdSec takes no responsibility for the security of your metabase instance. You used force yes, so you accept this disclaimer")

	return nil
}

func checkGroups(forceYes *bool) (*user.Group, error) {
	dockerGroup, err := user.LookupGroup(crowdsecGroup)
	if err == nil {
		return dockerGroup, nil
	}

	if !*forceYes {
		var answer bool

		prompt := &survey.Confirm{
			Message: fmt.Sprintf("For metabase docker to be able to access SQLite file we need to add a new group called '%s' to the system, is it ok for you ?", crowdsecGroup),
			Default: true,
		}

		if err := survey.AskOne(prompt, &answer); err != nil {
			return dockerGroup, fmt.Errorf("unable to ask to question: %s", err)
		}

		if !answer {
			return dockerGroup, fmt.Errorf("unable to continue without creating '%s' group", crowdsecGroup)
		}
	}

	groupAddCmd, err := exec.LookPath("groupadd")
	if err != nil {
		return dockerGroup, errors.New("unable to find 'groupadd' command, can't continue")
	}

	groupAdd := &exec.Cmd{Path: groupAddCmd, Args: []string{groupAddCmd, crowdsecGroup}}
	if err := groupAdd.Run(); err != nil {
		return dockerGroup, fmt.Errorf("unable to add group '%s': %s", dockerGroup, err)
	}

	return user.LookupGroup(crowdsecGroup)
}

func (cli *cliDashboard) chownDatabase(gid string) error {
	cfg := cli.cfg()
	intID, err := strconv.Atoi(gid)
	if err != nil {
		return fmt.Errorf("unable to convert group ID to int: %s", err)
	}

	if stat, err := os.Stat(cfg.DbConfig.DbPath); !os.IsNotExist(err) {
		info := stat.Sys()
		if err := os.Chown(cfg.DbConfig.DbPath, int(info.(*syscall.Stat_t).Uid), intID); err != nil {
			return fmt.Errorf("unable to chown sqlite db file '%s': %s", cfg.DbConfig.DbPath, err)
		}
	}

	if cfg.DbConfig.Type == "sqlite" && cfg.DbConfig.UseWal != nil && *cfg.DbConfig.UseWal {
		for _, ext := range []string{"-wal", "-shm"} {
			file := cfg.DbConfig.DbPath + ext
			if stat, err := os.Stat(file); !os.IsNotExist(err) {
				info := stat.Sys()
				if err := os.Chown(file, int(info.(*syscall.Stat_t).Uid), intID); err != nil {
					return fmt.Errorf("unable to chown sqlite db file '%s': %s", file, err)
				}
			}
		}
	}

	return nil
}
