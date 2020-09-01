package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

var download_only, force_install bool

func InstallItem(name string, obtype string) {
	for _, it := range cwhub.HubIdx[obtype] {
		if it.Name == name {
			if download_only && it.Downloaded && it.UpToDate {
				log.Warningf("%s is already downloaded and up-to-date", it.Name)
				return
			}
			it, err := cwhub.DownloadLatest(it, cwhub.Hubdir, force_install, config.DataFolder)
			if err != nil {
				log.Fatalf("error while downloading %s : %v", it.Name, err)
			}
			cwhub.HubIdx[obtype][it.Name] = it
			if download_only {
				log.Infof("Downloaded %s to %s", it.Name, cwhub.Hubdir+"/"+it.RemotePath)
				return
			}
			it, err = cwhub.EnableItem(it, cwhub.Installdir, cwhub.Hubdir)
			if err != nil {
				log.Fatalf("error while enabled %s : %v.", it.Name, err)
			}
			cwhub.HubIdx[obtype][it.Name] = it
			log.Infof("Enabled %s", it.Name)
			return
		}
	}
	log.Warningf("%s not found in hub index", name)
	/*iterate of pkg index data*/
}

func NewInstallCmd() *cobra.Command {
	/* ---- INSTALL COMMAND */

	var cmdInstall = &cobra.Command{
		Use:   "install [type] [config]",
		Short: "Install configuration(s) from hub",
		Long: `
Install configuration from the CrowdSec Hub.

In order to download latest versions of configuration, 
you should [update cscli](./cscli_update.md).

[type] must be parser, scenario, postoverflow, collection.

[config_name] must be a valid config name from [Crowdsec Hub](https://hub.crowdsec.net).
`,
		Example: `cscli install [type] [config_name]`,
		Args:    cobra.MinimumNArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !config.configured {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			if err := setHubBranch(); err != nil {
				return fmt.Errorf("error while setting hub branch: %s", err)
			}
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			log.Infof("Run 'systemctl reload crowdsec' for the new configuration to be effective.")
		},
	}
	cmdInstall.PersistentFlags().BoolVarP(&download_only, "download-only", "d", false, "Only download packages, don't enable")
	cmdInstall.PersistentFlags().BoolVar(&force_install, "force", false, "Force install : Overwrite tainted and outdated files")

	var cmdInstallParser = &cobra.Command{
		Use:     "parser [config]",
		Short:   "Install given parser",
		Long:    `Fetch and install given parser from hub`,
		Example: `cscli install parser crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			for _, name := range args {
				InstallItem(name, cwhub.PARSERS)
			}
		},
	}
	cmdInstall.AddCommand(cmdInstallParser)
	var cmdInstallScenario = &cobra.Command{
		Use:     "scenario [config]",
		Short:   "Install given scenario",
		Long:    `Fetch and install given scenario from hub`,
		Example: `cscli install scenario crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			for _, name := range args {
				InstallItem(name, cwhub.SCENARIOS)
			}
		},
	}
	cmdInstall.AddCommand(cmdInstallScenario)

	var cmdInstallCollection = &cobra.Command{
		Use:     "collection [config]",
		Short:   "Install given collection",
		Long:    `Fetch and install given collection from hub`,
		Example: `cscli install collection crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			for _, name := range args {
				InstallItem(name, cwhub.COLLECTIONS)
			}
		},
	}
	cmdInstall.AddCommand(cmdInstallCollection)

	var cmdInstallPostoverflow = &cobra.Command{
		Use:   "postoverflow [config]",
		Short: "Install given postoverflow parser",
		Long: `Fetch and install given postoverflow from hub.
As a reminder, postoverflows are parsing configuration that will occur after the overflow (before a decision is applied).`,
		Example: `cscli install collection crowdsec/xxx`,
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("failed to get Hub index : %v", err)
			}
			for _, name := range args {
				InstallItem(name, cwhub.PARSERS_OVFLW)
			}
		},
	}
	cmdInstall.AddCommand(cmdInstallPostoverflow)

	return cmdInstall
}
