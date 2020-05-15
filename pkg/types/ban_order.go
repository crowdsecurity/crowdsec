package types

import (
	"log"
	"net"
	"time"
)

//BanOrder is what is generated from a SignalOccurence : it describes what action to take
//it is in-memory only and never touches the DB. It will be turned into one or several "parser.BanApplication"
type BanOrder struct {
	MeasureSource string    /*api,local*/
	MeasureType   string    /*ban,slow,captcha*/
	Scope         string    /*ip,multi_ip,as,country*/
	TargetAS      int       /*if non-empty, applies to this AS*/
	TargetASName  string    /*if non-empty, applies to this AS*/
	TargetRange   net.IPNet /*if non-empty, applies to this IP*/
	TargetIP      net.IP    /*if non-empty, applies to this range*/
	TargetCountry string
	Until         time.Time /*when would the measure expire*/
	TxtTarget     string
	Reason        string
}

func OrderToApplications(ordr *BanOrder) ([]BanApplication, error) {
	var bas []BanApplication
	var ba BanApplication
	/*
		 pseudo-code for as/country scope would be :
		  - fetch ranges of AS/Country
		  - for ipnet := range Country.Ranges {
			  ba.append(...)
		  	  }
	*/

	ba.MeasureType = ordr.MeasureType
	ba.MeasureSource = ordr.MeasureSource
	ba.Until = ordr.Until
	ba.Reason = ordr.Reason
	ba.TargetAS = ordr.TargetAS
	ba.TargetASName = ordr.TargetASName

	ba.TargetCN = ordr.TargetCountry
	if ordr.Scope == "ip" {
		ba.StartIp = IP2Int(ordr.TargetIP)
		ba.EndIp = IP2Int(ordr.TargetIP)
		ba.IpText = ordr.TargetIP.String()
		bas = append(bas, ba)
	} else if ordr.Scope == "range" {
		ba.StartIp = IP2Int(ordr.TargetRange.IP)
		ba.EndIp = IP2Int(LastAddress(&ordr.TargetRange))
		ba.IpText = ordr.TargetRange.String()
		bas = append(bas, ba)
	} else {
		log.Fatalf("only 'ip' and 'range' scopes are supported.")
	}
	return bas, nil
}
