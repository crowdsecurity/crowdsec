package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"

	"github.com/enescakir/emoji"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var upgrade_all, force_upgrade bool

func UpgradeConfig(ttype string, name string) {
	var err error
	var updated int
	var found bool

	for _, v := range cwhub.HubIdx[ttype] {
		//name mismatch
		if name != "" && name != v.Name {
			continue
		}
		if !v.Installed {
			log.Debugf("skip %s, not installed", v.Name)
			continue
		}
		if !v.Downloaded {
			log.Warningf("%s : not downloaded, please install.", v.Name)
			continue
		}
		found = true
		if v.UpToDate {
			log.Infof("%s : up-to-date", v.Name)
			continue
		}
		v, err = cwhub.DownloadLatest(v, cwhub.Hubdir, force_upgrade)
		if err != nil {
			log.Fatalf("%s : download failed : %v", v.Name, err)
		}
		if !v.UpToDate {
			if v.Tainted {
				log.Infof("%v %s is tainted, --force to overwrite", emoji.Warning, v.Name)
			} else if v.Local {
				log.Infof("%v %s is local", emoji.Prohibited, v.Name)
			}
		} else {
			log.Infof("%v %s : updated", emoji.Package, v.Name)
			updated += 1
		}
		cwhub.HubIdx[ttype][v.Name] = v
	}
	if found == false {
		log.Errorf("Didn't find %s", name)
	} else if updated == 0 && found == true {
		log.Errorf("Nothing to update")
	} else if updated != 0 {
		log.Infof("Upgraded %d items", updated)
	}

}

func NewUpgradeCmd() *cobra.Command {

	var cmdUpgrade = &cobra.Command{
		Use:   "upgrade [type] [config]",
		Short: "Upgrade configuration(s)",
		Long: `
Upgrade configuration from the CrowdSec Hub.

In order to upgrade latest versions of configuration, 
the Hub cache should be [updated](./cscli_update.md).
 
Tainted configuration will not be updated (use --force to update them).

[type] must be parser, scenario, postoverflow, collection.

[config_name] must be a valid config name from [Crowdsec Hub](https://hub.crowdsec.net).
 

 `,
		Example: `cscli upgrade [type] [config_name]
cscli upgrade --all   # Upgrade all configurations types
cscli upgrade --force # Overwrite tainted configuration
		`,

		Args: cobra.MinimumNArgs(0),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !config.configured {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			if upgrade_all == false && len(args) < 2 {
				_ = cmd.Help()
				return
			}
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if upgrade_all == true && len(args) == 0 {
				log.Warningf("Upgrade all : parsers, scenarios, collections.")
				UpgradeConfig(cwhub.PARSERS, "")
				UpgradeConfig(cwhub.PARSERS_OVFLW, "")
				UpgradeConfig(cwhub.SCENARIOS, "")
				UpgradeConfig(cwhub.COLLECTIONS, "")
			}
			//fmt.Println("upgrade all ?!: " + strings.Join(args, " "))
		},
	}
	cmdUpgrade.PersistentFlags().BoolVar(&upgrade_all, "all", false, "Upgrade all configuration in scope")
	cmdUpgrade.PersistentFlags().BoolVar(&force_upgrade, "force", false, "Overwrite existing files, even if tainted")
	var cmdUpgradeParser = &cobra.Command{
		Use:   "parser [config]",
		Short: "Upgrade parser configuration(s)",
		Long:  `Upgrade one or more parser configurations`,
		Example: ` - cscli upgrade parser crowdsec/apache-logs  
 - cscli upgrade parser -all  
 - cscli upgrade parser crowdsec/apache-logs --force`,
		Args: cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if len(args) == 1 {
				UpgradeConfig(cwhub.PARSERS, args[0])
				//UpgradeConfig(cwhub.PARSERS_OVFLW, "")
			} else if upgrade_all == true {
				UpgradeConfig(cwhub.PARSERS, "")
			} else {
				_ = cmd.Help()
			}
		},
	}
	cmdUpgrade.AddCommand(cmdUpgradeParser)
	var cmdUpgradeScenario = &cobra.Command{
		Use:   "scenario [config]",
		Short: "Upgrade scenario configuration(s)",
		Long:  `Upgrade one or more scenario configurations`,
		Example: ` - cscli	upgrade scenario -all  
 - cscli upgrade scenario crowdsec/http-404 --force  `,
		Args: cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if len(args) == 1 {
				UpgradeConfig(cwhub.SCENARIOS, args[0])
			} else if upgrade_all == true {
				UpgradeConfig(cwhub.SCENARIOS, "")
			} else {
				_ = cmd.Help()
			}
		},
	}
	cmdUpgrade.AddCommand(cmdUpgradeScenario)
	var cmdUpgradeCollection = &cobra.Command{
		Use:   "collection [config]",
		Short: "Upgrade collection configuration(s)",
		Long:  `Upgrade one or more collection configurations`,
		Example: ` - cscli upgrade collection crowdsec/apache-lamp  
 - cscli upgrade collection -all  
 - cscli upgrade collection crowdsec/apache-lamp --force`,
		Args: cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if len(args) == 1 {
				UpgradeConfig(cwhub.COLLECTIONS, args[0])
			} else if upgrade_all == true {
				UpgradeConfig(cwhub.COLLECTIONS, "")
			} else {
				_ = cmd.Help()
			}
		},
	}
	cmdUpgrade.AddCommand(cmdUpgradeCollection)

	var cmdUpgradePostoverflow = &cobra.Command{
		Use:   "postoverflow [config]",
		Short: "Upgrade postoverflow parser configuration(s)",
		Long:  `Upgrade one or more postoverflow parser configurations`,
		Example: ` - cscli upgrade postoverflow crowdsec/enrich-rdns  
 - cscli upgrade postoverflow -all  
 - cscli upgrade postoverflow crowdsec/enrich-rdns --force`,
		Args: cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.GetHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
			if len(args) == 1 {
				UpgradeConfig(cwhub.PARSERS_OVFLW, args[0])
			} else if upgrade_all == true {
				UpgradeConfig(cwhub.PARSERS_OVFLW, "")
			} else {
				_ = cmd.Help()
			}
		},
	}
	cmdUpgrade.AddCommand(cmdUpgradePostoverflow)
	return cmdUpgrade
}
