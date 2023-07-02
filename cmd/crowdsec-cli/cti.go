package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient"
	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func CTIToTable(item *cticlient.SmokeItem) error {
	switch csConfig.Cscli.Output {
	case "json":
		x, _ := json.MarshalIndent(item, "", " ")
		fmt.Printf("%s", string(x))
	case "human":
		if item.Ip == "" {
			fmt.Println("No result")
			return nil
		}
		ctiTable(color.Output, item)
	case "raw":
		// TODO : implement raw output
		//	header := []string{"ip", "range", "as", "location", "history", "classification"}
		//	csvwriter := csv.NewWriter(os.Stdout)
		//	err := csvwriter.Write(header)
		//	if err != nil {
		//		return err
		//	}

		//	countryString := ""
		//	if item.Location.City != nil {
		//		countryString = fmt.Sprintf("Country: %s City: %s", *item.Location.Country, *item.Location.City)
		//	} else {
		//		countryString = fmt.Sprintf("Country: %s", *item.Location.Country)
		//	}
		//	err = csvwriter.Write([]string{
		//		item.Ip,
		//		*item.IpRange,
		//		fmt.Sprintf("AS Name: %s AS Number: %d", *item.AsName, *item.AsNum),
		//		countryString,
		//		fmt.Sprintf("First Seen: %s Last Seen: %s", *item.History.FirstSeen, *item.History.LastSeen),
		//		classificationToString(item, false),
		//	})
		//	if err != nil {
		//		return err
		//	}
		//	csvwriter.Flush()
	}
	return nil
}

func NewCTICmd() *cobra.Command {
	var cmdCTI = &cobra.Command{
		Use:               "cti [action]",
		Short:             "Query CrowdSec CTI API",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if csConfig.Cscli.Output == "raw" {
				return fmt.Errorf("raw output format is not supported for this command")
			}
			if key, _ := cmd.Flags().GetString("key"); csConfig.API.CTI != nil && *csConfig.API.CTI.Key != "" && key == "" {
				log.Debug("Using API key from config file")
				cmd.Flags().Set("key", *csConfig.API.CTI.Key)
			}
			if key, _ := cmd.Flags().GetString("key"); key == "" {
				return fmt.Errorf("no API key provided")
			}
			return nil
		},
	}
	cmdCTI.Flags().SortFlags = false
	cmdCTI.PersistentFlags().StringP("key", "k", "", "API key to use")
	cmdCTI.AddCommand(CTISearchCmd())

	return cmdCTI
}

func CTISearchCmd() *cobra.Command {
	var cmdCTISearch = &cobra.Command{
		Use:               "search [ip]",
		Short:             "Search for an IP in the CTI database",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if ip := net.ParseIP(strings.TrimSpace(arg)); ip == nil {
					return fmt.Errorf("invalid IP address '%s'", arg)
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			key, _ := cmd.Flags().GetString("key")
			ctiClient := cticlient.NewCrowdsecCTIClient(cticlient.WithAPIKey(key))
			item, err := ctiClient.GetIPInfo(args[0])
			if err != nil {
				return err
			}
			CTIToTable(item)
			return nil
		},
	}
	return cmdCTISearch
}
