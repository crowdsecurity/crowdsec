package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewUpdateCmd() *cobra.Command {
	/* ---- UPDATE COMMAND */
	var cmdUpdate = &cobra.Command{
		Use:   "update",
		Short: "Fetch available configs from hub",
		Long: `
Fetches the [.index.json](https://github.com/crowdsecurity/hub/blob/master/.index.json) file from hub, containing the list of available configs.
`,
		Args: cobra.ExactArgs(0),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !config.configured {
				return fmt.Errorf("you must configure cli before interacting with hub")
			}

			if cwhub.HubBranch == "" {
				latest, err := cwversion.Latest()
				if err != nil {
					log.Fatalf("unable to get last crowdsec version: %s", err)
				}

				if cwversion.Version == latest {
					cwhub.HubBranch = "master"
				} else {
					log.Warnf("Crowdsec is not the latest version. Current version is '%s' and latest version is '%s'. Please update it!", cwversion.Version, latest)
					cwhub.HubBranch = cwversion.Version
				}
				log.Debugf("Using branch '%s' for the hub", cwhub.HubBranch)
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			if err := cwhub.UpdateHubIdx(); err != nil {
				log.Fatalf("Failed to get Hub index : %v", err)
			}
		},
	}
	return cmdUpdate
}
