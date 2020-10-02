package main

import (
	"fmt"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
)

var remediationType string
var atTime string

//user supplied filters
var ipFilter, rangeFilter, reasonFilter, countryFilter, asFilter string
var displayLimit int
var displayAPI, displayALL bool

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
					log.Tracef("[keep] ip filter is set, and range contains ip")
					keep = true
				} else {
					log.Tracef("[discard] ip filter is set, and range doesn't contain ip")
					keep = false
				}
			} else {
				if ipFilter == ban["iptext"] {
					log.Tracef("[keep] (ip) %s == %s", ipFilter, ban["iptext"])
					keep = true
				} else {
					log.Tracef("[discard] (ip) %s == %s", ipFilter, ban["iptext"])
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
				log.Tracef("[keep] range filter %s contains %s", rangeFilter, banIP.String())
				keep = true
			} else {
				log.Tracef("[discard] range filter %s doesn't contain %s", rangeFilter, banIP.String())
				keep = false
			}
		}
		if reasonFilter != "" {
			if strings.Contains(ban["reason"], reasonFilter) {
				log.Tracef("[keep] reason filter %s matches %s", reasonFilter, ban["reason"])
				keep = true
			} else {
				log.Tracef("[discard] reason filter %s doesn't match %s", reasonFilter, ban["reason"])
				keep = false
			}
		}

		if countryFilter != "" {
			if ban["cn"] == countryFilter {
				log.Tracef("[keep] country filter %s matches %s", countryFilter, ban["cn"])
				keep = true
			} else {
				log.Tracef("[discard] country filter %s matches %s", countryFilter, ban["cn"])
				keep = false
			}
		}

		if asFilter != "" {
			if strings.Contains(ban["as"], asFilter) {
				log.Tracef("[keep] AS filter %s matches %s", asFilter, ban["as"])
				keep = true
			} else {
				log.Tracef("[discard] AS filter %s doesn't match %s", asFilter, ban["as"])
				keep = false
			}
		}

		if keep {
			retBans = append(retBans, ban)
		} else {
			log.Tracef("[discard] discard %v", ban)
		}
	}
	return retBans, nil
}
