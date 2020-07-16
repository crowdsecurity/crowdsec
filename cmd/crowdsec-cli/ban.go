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

//user supplied filters
var ipFilter, rangeFilter, reasonFilter, countryFilter, asFilter string
var displayLimit int
var displayAPI, displayALL bool

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

	var banApps = make([]types.BanApplication, 0)
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

func filterBans(bans []map[string]string) ([]map[string]string, error) {

	var retBans []map[string]string

	for _, ban := range bans {
		var banIP net.IP
		var banRange *net.IPNet
		var keep bool = true
		var err error

		if ban["iptext"] != "" {
			if strings.Contains(ban["iptext"], "/") {
				log.Debugf("%s is a range", ban["iptext"])
				banIP, banRange, err = net.ParseCIDR(ban["iptext"])
				if err != nil {
					log.Warningf("failed to parse range '%s' from database : %s", ban["iptext"], err)
				}
			} else {
				log.Debugf("%s is IP", ban["iptext"])
				banIP = net.ParseIP(ban["iptext"])
			}
		}

		if ipFilter != "" {
			var filterBinIP net.IP = net.ParseIP(ipFilter)

			if banRange != nil {
				if banRange.Contains(filterBinIP) {
					log.Debugf("[keep] ip filter is set, and range contains ip")
					keep = true
				} else {
					log.Debugf("[discard] ip filter is set, and range doesn't contain ip")
					keep = false
				}
			} else {
				if ipFilter == ban["iptext"] {
					log.Debugf("[keep] (ip) %s == %s", ipFilter, ban["iptext"])
					keep = true
				} else {
					log.Debugf("[discard] (ip) %s == %s", ipFilter, ban["iptext"])
					keep = false
				}
			}
		}
		if rangeFilter != "" {
			_, filterBinRange, err := net.ParseCIDR(rangeFilter)
			if err != nil {
				return nil, fmt.Errorf("failed to parse range '%s' : %s", rangeFilter, err)
			}
			if filterBinRange.Contains(banIP) {
				log.Debugf("[keep] range filter %s contains %s", rangeFilter, banIP.String())
				keep = true
			} else {
				log.Debugf("[discard] range filter %s doesn't contain %s", rangeFilter, banIP.String())
				keep = false
			}
		}
		if reasonFilter != "" {
			if strings.Contains(ban["reason"], reasonFilter) {
				log.Debugf("[keep] reason filter %s matches %s", reasonFilter, ban["reason"])
				keep = true
			} else {
				log.Debugf("[discard] reason filter %s doesn't match %s", reasonFilter, ban["reason"])
				keep = false
			}
		}

		if countryFilter != "" {
			if ban["cn"] == countryFilter {
				log.Debugf("[keep] country filter %s matches %s", countryFilter, ban["cn"])
				keep = true
			} else {
				log.Debugf("[discard] country filter %s matches %s", countryFilter, ban["cn"])
				keep = false
			}
		}

		if asFilter != "" {
			if strings.Contains(ban["as"], asFilter) {
				log.Debugf("[keep] AS filter %s matches %s", asFilter, ban["as"])
				keep = true
			} else {
				log.Debugf("[discard] AS filter %s doesn't match %s", asFilter, ban["as"])
				keep = false
			}
		}

		if keep {
			retBans = append(retBans, ban)
		} else {
			log.Debugf("[discard] discard %v", ban)
		}
	}
	return retBans, nil
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
		return fmt.Errorf("unable to get records from Database : %v", err)
	}
	ret, err = filterBans(ret)
	if err != nil {
		log.Errorf("Error while filtering : %s", err)
	}
	if config.output == "raw" {
		fmt.Printf("source,ip,reason,bans,action,country,as,events_count,expiration\n")
		for _, rm := range ret {
			fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n", rm["source"], rm["iptext"], rm["reason"], rm["bancount"], rm["action"], rm["cn"], rm["as"], rm["events_count"], rm["until"])
		}
	} else if config.output == "json" {
		x, _ := json.MarshalIndent(ret, "", " ")
		fmt.Printf("%s", string(x))
	} else if config.output == "human" {

		uniqAS := map[string]bool{}
		uniqCN := map[string]bool{}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Source", "Ip", "Reason", "Bans", "Action", "Country", "AS", "Events", "Expiration"})

		dispcount := 0
		apicount := 0
		for _, rm := range ret {
			if !displayAPI && rm["source"] == "api" {
				apicount++
				if _, ok := uniqAS[rm["as"]]; !ok {
					uniqAS[rm["as"]] = true
				}
				if _, ok := uniqCN[rm["cn"]]; !ok {
					uniqCN[rm["cn"]] = true
				}
			}
			if displayALL {
				if rm["source"] == "api" {
					if displayAPI {
						table.Append([]string{rm["source"], rm["iptext"], rm["reason"], rm["bancount"], rm["action"], rm["cn"], rm["as"], rm["events_count"], rm["until"]})
						dispcount++
						continue
					}
				} else {
					table.Append([]string{rm["source"], rm["iptext"], rm["reason"], rm["bancount"], rm["action"], rm["cn"], rm["as"], rm["events_count"], rm["until"]})
					dispcount++
					continue
				}
			} else if dispcount < displayLimit {
				if displayAPI {
					if rm["source"] == "api" {
						table.Append([]string{rm["source"], rm["iptext"], rm["reason"], rm["bancount"], rm["action"], rm["cn"], rm["as"], rm["events_count"], rm["until"]})
						dispcount++
						continue
					}
				} else {
					if rm["source"] != "api" {
						table.Append([]string{rm["source"], rm["iptext"], rm["reason"], rm["bancount"], rm["action"], rm["cn"], rm["as"], rm["events_count"], rm["until"]})
						dispcount++
						continue
					}
				}
			}
		}
		if dispcount > 0 {
			if !displayAPI {
				fmt.Printf("%d local decisions:\n", dispcount)
			} else if displayAPI && !displayALL {
				fmt.Printf("%d decision from API\n", dispcount)
			} else if displayALL && displayAPI {
				fmt.Printf("%d decision from crowdsec and API\n", dispcount)
			}
			table.Render() // Send output
			if dispcount > displayLimit && !displayALL {
				fmt.Printf("Additional records stripped.\n")
			}
		} else {
			if displayAPI {
				fmt.Println("No API decisions")
			} else {
				fmt.Println("No local decisions")
			}
		}
		if !displayAPI {
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
		Args:    cobra.MinimumNArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			reason := strings.Join(args[2:], " ")
			if err := BanAdd(args[0], args[1], reason, remediationType); err != nil {
				log.Fatalf("failed to add ban to database : %v", err)
			}
		},
	}
	cmdBanAdd.AddCommand(cmdBanAddIp)
	var cmdBanAddRange = &cobra.Command{
		Use:     "range <target> <duration> <reason>",
		Short:   "Adds the specific ip to the ban db",
		Long:    `Duration must be [time.ParseDuration](https://golang.org/pkg/time/#ParseDuration) compatible, expressed in s/m/h.`,
		Example: `cscli ban add range 1.2.3.0/24 12h "the whole range"`,
		Args:    cobra.MinimumNArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			reason := strings.Join(args[2:], " ")
			if err := BanAdd(args[0], args[1], reason, remediationType); err != nil {
				log.Fatalf("failed to add ban to database : %v", err)
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

If --all/-a is specified, bans will be displayed without limit (--limit).
Default limit is 50.

Time can be specified with --at and support a variety of date formats:  
 - Jan  2 15:04:05  
 - Mon Jan 02 15:04:05.000000 2006  
 - 2006-01-02T15:04:05Z07:00  
 - 2006/01/02  
 - 2006/01/02 15:04  
 - 2006-01-02  
 - 2006-01-02 15:04
`,
		Example: `ban list --range 0.0.0.0/0 : will list all
		ban list --country CN
		ban list --reason crowdsecurity/http-probing
		ban list --as OVH`,
		Args: cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := BanList(); err != nil {
				log.Fatalf("failed to list bans : %v", err)
			}
		},
	}
	cmdBanList.PersistentFlags().StringVar(&atTime, "at", "", "List bans at given time")
	cmdBanList.PersistentFlags().BoolVarP(&displayALL, "all", "a", false, "List bans without limit")
	cmdBanList.PersistentFlags().BoolVarP(&displayAPI, "api", "", false, "List as well bans received from API")
	cmdBanList.PersistentFlags().StringVar(&ipFilter, "ip", "", "List bans for given IP")
	cmdBanList.PersistentFlags().StringVar(&rangeFilter, "range", "", "List bans belonging to given range")
	cmdBanList.PersistentFlags().StringVar(&reasonFilter, "reason", "", "List bans containing given reason")
	cmdBanList.PersistentFlags().StringVar(&countryFilter, "country", "", "List bans belonging to given country code")
	cmdBanList.PersistentFlags().StringVar(&asFilter, "as", "", "List bans belonging to given AS name")
	cmdBanList.PersistentFlags().IntVar(&displayLimit, "limit", 50, "Limit of bans to display (default 50)")

	cmdBan.AddCommand(cmdBanList)
	return cmdBan
}
