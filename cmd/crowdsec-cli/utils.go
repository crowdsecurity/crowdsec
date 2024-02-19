package main

import (
	"fmt"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func printHelp(cmd *cobra.Command) {
	if err := cmd.Help(); err != nil {
		log.Fatalf("unable to print help(): %s", err)
	}
}

func manageCliDecisionAlerts(ip *string, ipRange *string, scope *string, value *string) error {
	/*if a range is provided, change the scope*/
	if *ipRange != "" {
		_, _, err := net.ParseCIDR(*ipRange)
		if err != nil {
			return fmt.Errorf("%s isn't a valid range", *ipRange)
		}
	}
	if *ip != "" {
		ipRepr := net.ParseIP(*ip)
		if ipRepr == nil {
			return fmt.Errorf("%s isn't a valid ip", *ip)
		}
	}

	//avoid confusion on scope (ip vs Ip and range vs Range)
	switch strings.ToLower(*scope) {
	case "ip":
		*scope = types.Ip
	case "range":
		*scope = types.Range
	case "country":
		*scope = types.Country
	case "as":
		*scope = types.AS
	}
	return nil
}

func getDBClient() (*database.Client, error) {
	if err := csConfig.LoadAPIServer(); err != nil || csConfig.DisableAPI {
		return nil, err
	}
	ret, err := database.NewClient(csConfig.DbConfig)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func removeFromSlice(val string, slice []string) []string {
	var i int
	var value string

	valueFound := false

	// get the index
	for i, value = range slice {
		if value == val {
			valueFound = true
			break
		}
	}

	if valueFound {
		slice[i] = slice[len(slice)-1]
		slice[len(slice)-1] = ""
		slice = slice[:len(slice)-1]
	}

	return slice
}
