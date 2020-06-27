package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/outputs"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"

	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var remediationType string
var atTime string
var all bool

func simpleBanToSignal(targetIP string, reason string, expirationStr string, action string, asName string, asNum string, country string, banSource string) (types.SignalOccurence, error) {
	var signalOcc types.SignalOccurence

	expiration, err := time.ParseDuration(expirationStr)
	if err != nil {
		return signalOcc, err
	}

	asOrgInt := 0
	if asNum != "" {
		asOrgInt, err = strconv.Atoi(asNum)
		if err != nil {
			log.Infof("Invalid as value %s : %s", asNum, err)
		}
	}

	banApp := types.BanApplication{
		MeasureSource: banSource,
		MeasureType:   action,
		Until:         time.Now().Add(expiration),
		IpText:        targetIP,
		TargetCN:      country,
		TargetAS:      asOrgInt,
		TargetASName:  asName,
		Reason:        reason,
	}
	var parsedIP net.IP
	var parsedRange *net.IPNet
	if strings.Contains(targetIP, "/") {
		if _, parsedRange, err = net.ParseCIDR(targetIP); err != nil {
			return signalOcc, fmt.Errorf("'%s' is not a valid CIDR", targetIP)
		}
		if parsedRange == nil {
			return signalOcc, fmt.Errorf("unable to parse network : %s", err)
		}
		banApp.StartIp = types.IP2Int(parsedRange.IP)
		banApp.EndIp = types.IP2Int(types.LastAddress(parsedRange))
	} else {
		parsedIP = net.ParseIP(targetIP)
		if parsedIP == nil {
			return signalOcc, fmt.Errorf("'%s' is not a valid IP", targetIP)
		}
		banApp.StartIp = types.IP2Int(parsedIP)
		banApp.EndIp = types.IP2Int(parsedIP)
	}

	var banApps = make([]types.BanApplication, 1)
	banApps = append(banApps, banApp)
	signalOcc = types.SignalOccurence{
		Scenario:                            reason,
		Events_count:                        1,
		Start_at:                            time.Now(),
		Stop_at:                             time.Now(),
		BanApplications:                     banApps,
		Source_ip:                           targetIP,
		Source_AutonomousSystemNumber:       asNum,
		Source_AutonomousSystemOrganization: asName,
		Source_Country:                      country,
	}
	return signalOcc, nil
}

func BanList() error {
	at := time.Now()
	if atTime != "" {
		_, at = parser.GenDateParse(atTime)
		if at.IsZero() {
			return fmt.Errorf("unable to parse date '%s'", atTime)
		}
	}
	ret, err := outputCTX.ReadAT(at)
	if err != nil {
		return fmt.Errorf("unable to get records from sqlite : %v", err)
	}
	if config.output == "json" {
		x, _ := json.MarshalIndent(ret, "", " ")
		fmt.Printf("%s", string(x))
	} else if config.output == "human" {

		uniqAS := map[string]bool{}
		uniqCN := map[string]bool{}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Source", "Ip", "Reason", "Bans", "Action", "Country", "AS", "Events", "Expiration"})

		dispcount := 0
		totcount := 0
		apicount := 0
		for _, rm := range ret {
			if !all && rm["source"] == "api" {
				apicount++
				if _, ok := uniqAS[rm["as"]]; !ok {
					uniqAS[rm["as"]] = true
				}
				if _, ok := uniqCN[rm["cn"]]; !ok {
					uniqCN[rm["cn"]] = true
				}
				continue
			}
			if dispcount < 20 {
				table.Append([]string{rm["source"], rm["iptext"], rm["reason"], rm["bancount"], rm["action"], rm["cn"], rm["as"], rm["events_count"], rm["until"]})
			}
			totcount++
			dispcount++

		}
		if dispcount > 0 {
			if !all {
				fmt.Printf("%d local decisions:\n", totcount)
			}
			table.Render() // Send output
			if dispcount > 20 {
				fmt.Printf("Additional records stripped.\n")
			}
		} else {
			fmt.Printf("No local decisions.\n")
		}
		if !all {
			fmt.Printf("And %d records from API, %d distinct AS, %d distinct countries\n", apicount, len(uniqAS), len(uniqCN))
		}
	}
	return nil
}

func BanAdd(target string, duration string, reason string, action string) error {
	var signalOcc types.SignalOccurence
	var err error

	signalOcc, err = simpleBanToSignal(target, reason, duration, action, "", "", "", "cli")
	if err != nil {
		return fmt.Errorf("unable to insert ban : %v", err)
	}
	err = outputCTX.Insert(signalOcc)
	if err != nil {
		return err
	}
	err = outputCTX.Flush()
	if err != nil {
		return err
	}
	log.Infof("%s %s for %s (%s)", action, target, duration, reason)
	return nil
}

func NewBanCmds() *cobra.Command {
	/*TODO : add a remediation type*/
	var cmdBan = &cobra.Command{
		Use:   "ban [command] <target> <duration> <reason>",
		Short: "Manage bans/mitigations",
		Long: `This is the main interaction point with local ban database for humans.

You can add/delete/list or flush current bans in your local ban DB.`,
		Args: cobra.MinimumNArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if !config.configured {
				return fmt.Errorf("you must configure cli before using bans")
			}

			outputConfig := outputs.OutputFactory{
				BackendFolder: config.BackendPluginFolder,
				Flush:         false,
			}

			outputCTX, err = outputs.NewOutput(&outputConfig)
			if err != nil {
				return fmt.Errorf(err.Error())
			}
			return nil
		},
	}
	cmdBan.PersistentFlags().StringVar(&remediationType, "remediation", "ban", "Set specific remediation type : ban|slow|captcha")
	cmdBan.Flags().SortFlags = false
	cmdBan.PersistentFlags().SortFlags = false

	var cmdBanAdd = &cobra.Command{
		Use:   "add [ip|range] <target> <duration> <reason>",
		Short: "Adds a ban against a given ip/range for the provided duration",
		Long: `
Allows to add a ban against a specific ip or range target for a specific duration.  

The duration argument can be expressed in seconds(s), minutes(m) or hours (h).
		
See [time.ParseDuration](https://golang.org/pkg/time/#ParseDuration) for more informations.`,
		Example: `cscli ban add ip 1.2.3.4 24h "scan"  
cscli ban add range 1.2.3.0/24 24h "the whole range"`,
		Args: cobra.MinimumNArgs(4),
	}
	cmdBan.AddCommand(cmdBanAdd)
	var cmdBanAddIp = &cobra.Command{
		Use:     "ip <target> <duration> <reason>",
		Short:   "Adds the specific ip to the ban db",
		Long:    `Duration must be [time.ParseDuration](https://golang.org/pkg/time/#ParseDuration), expressed in s/m/h.`,
		Example: `cscli ban add ip 1.2.3.4 12h "the scan"`,
		Args:    cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			if err := BanAdd(args[0], args[1], args[2], remediationType); err != nil {
				log.Fatalf("failed to add ban to sqlite : %v", err)
			}
		},
	}
	cmdBanAdd.AddCommand(cmdBanAddIp)
	var cmdBanAddRange = &cobra.Command{
		Use:     "range <target> <duration> <reason>",
		Short:   "Adds the specific ip to the ban db",
		Long:    `Duration must be [time.ParseDuration](https://golang.org/pkg/time/#ParseDuration) compatible, expressed in s/m/h.`,
		Example: `cscli ban add range 1.2.3.0/24 12h "the whole range"`,
		Args:    cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			if err := BanAdd(args[0], args[1], args[2], remediationType); err != nil {
				log.Fatalf("failed to add ban to sqlite : %v", err)
			}
		},
	}
	cmdBanAdd.AddCommand(cmdBanAddRange)
	var cmdBanDel = &cobra.Command{
		Use:   "del [command] <target>",
		Short: "Delete bans from db",
		Long:  "The removal of the bans can be applied on a single IP address or directly on a IP range.",
		Example: `cscli ban del ip 1.2.3.4  
cscli ban del range 1.2.3.0/24`,
		Args: cobra.MinimumNArgs(2),
	}
	cmdBan.AddCommand(cmdBanDel)

	var cmdBanFlush = &cobra.Command{
		Use:     "flush",
		Short:   "Fush ban DB",
		Example: `cscli ban flush`,
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if err := outputCTX.DeleteAll(); err != nil {
				log.Fatalf(err.Error())
			}
			log.Printf("Ban DB flushed")
		},
	}
	cmdBan.AddCommand(cmdBanFlush)
	var cmdBanDelIp = &cobra.Command{
		Use:     "ip <target>",
		Short:   "Delete bans for given ip from db",
		Example: `cscli ban del ip 1.2.3.4`,
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			count, err := outputCTX.Delete(args[0])
			if err != nil {
				log.Fatalf("failed to delete %s : %v", args[0], err)
			}
			log.Infof("Deleted %d entries", count)
		},
	}
	cmdBanDel.AddCommand(cmdBanDelIp)
	var cmdBanDelRange = &cobra.Command{
		Use:     "range <target>",
		Short:   "Delete bans for given ip from db",
		Example: `cscli ban del range 1.2.3.0/24`,
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			count, err := outputCTX.Delete(args[0])
			if err != nil {
				log.Fatalf("failed to delete %s : %v", args[0], err)
			}
			log.Infof("Deleted %d entries", count)
		},
	}
	cmdBanDel.AddCommand(cmdBanDelRange)

	var cmdBanList = &cobra.Command{
		Use:   "list",
		Short: "List local or api bans/remediations",
		Long: `List the bans, by default only local decisions.

If --all/-a is specified, api-provided bans will be displayed too.

Time can be specified with --at and support a variety of date formats:  
 - Jan  2 15:04:05  
 - Mon Jan 02 15:04:05.000000 2006  
 - 2006-01-02T15:04:05Z07:00  
 - 2006/01/02  
 - 2006/01/02 15:04  
 - 2006-01-02  
 - 2006-01-02 15:04
`,
		Args: cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := BanList(); err != nil {
				log.Fatalf("failed to list bans : %v", err)
			}
		},
	}
	cmdBanList.PersistentFlags().StringVar(&atTime, "at", "", "List bans at given time")
	cmdBanList.PersistentFlags().BoolVarP(&all, "all", "a", false, "List as well bans received from API")
	cmdBan.AddCommand(cmdBanList)
	return cmdBan
}
