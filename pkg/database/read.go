package database

import (
	"fmt"
	"strconv"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/jinzhu/gorm"
	log "github.com/sirupsen/logrus"
)

//GetBansAt returns the IPs that were banned at a given time
func (c *Context) GetBansAt(at time.Time) ([]map[string]string, error) {

	bas := []types.BanApplication{}
	rets := make([]map[string]string, 0)
	/*get non-expired records*/
	//c.Db.LogMode(true)
	//records := c.Db.Order("updated_at desc").Where(`strftime("%s", until) >= strftime("%s", ?) AND strftime("%s", created_at) < strftime("%s", ?)`, at, at).Group("ip_text").Find(&bas) /*.Count(&count)*/
	records := c.Db.Order("updated_at desc").Where("until >= ? AND created_at < ?", at, at).Group("ip_text").Find(&bas) /*.Count(&count)*/
	if records.Error != nil {
		return nil, records.Error
	}
	for _, ba := range bas {
		var count int
		/*
		 fetch count of bans for this specific ip_text
		*/
		//ret := c.Db.Table("ban_applications").Order("updated_at desc").Where(`ip_text = ? AND strftime("%s", until) >= strftime("%s", ?) AND strftime("%s", created_at) < strftime("%s", ?) AND deleted_at is NULL`, ba.IpText, at, at).Count(&count)
		ret := c.Db.Table("ban_applications").Order("updated_at desc").Where(`ip_text = ? AND until >= ? AND created_at < ? AND deleted_at is NULL`, ba.IpText, at, at).Count(&count)
		if ret.Error != nil {
			return nil, fmt.Errorf("failed to fetch records count for %s : %v", ba.IpText, ret.Error)
		}
		sOs := []types.SignalOccurence{}
		nbSo := 0
		records := c.Db.Where(`source_ip = ?`, ba.IpText).Group("id").Find(&sOs).Count(&nbSo)
		if records.Error != nil {
			//record not found can be ok
			if gorm.IsRecordNotFoundError(records.Error) {
				bancom := make(map[string]string)
				bancom["iptext"] = ba.IpText
				bancom["bancount"] = fmt.Sprintf("%d", count)
				bancom["as"] = ba.TargetASName
				bancom["asnum"] = fmt.Sprintf("%d", ba.TargetAS)
				bancom["cn"] = ba.TargetCN
				bancom["scenario"] = "?"
				bancom["source"] = ba.MeasureSource
				bancom["events_count"] = "0"
				bancom["action"] = ba.MeasureType
				bancom["until"] = time.Until(ba.Until).Round(time.Second).String()
				bancom["reason"] = ba.Reason
				rets = append(rets, bancom)
				continue
			}
		}

		evtCount := 0
		for _, s := range sOs {
			evtCount += s.Events_count
		}

		so := types.SignalOccurence{}
		records = c.Db.Where(`id = ?`, ba.SignalOccurenceID).Find(&so)
		if records.Error != nil {
			//record not found can be ok
			if gorm.IsRecordNotFoundError(records.Error) {
				bancom := make(map[string]string)
				bancom["iptext"] = ba.IpText
				bancom["bancount"] = fmt.Sprintf("%d", count)
				bancom["as"] = ba.TargetASName
				bancom["asnum"] = fmt.Sprintf("%d", ba.TargetAS)
				bancom["cn"] = ba.TargetCN
				bancom["source"] = ba.MeasureSource
				bancom["scenario"] = "?"
				bancom["events_count"] = "0"
				bancom["action"] = ba.MeasureType
				bancom["until"] = time.Until(ba.Until).Round(time.Second).String()
				bancom["reason"] = ba.Reason
				rets = append(rets, bancom)
				continue
			}
			fmt.Printf("err : %v", records.Error)
			return nil, records.Error
		}
		if records.RowsAffected != 1 {
			log.Errorf("more than one signal_occurence for local_decision, discard")
			break
		}
		bancom := make(map[string]string)
		bancom["iptext"] = ba.IpText
		bancom["as"] = so.Source_AutonomousSystemNumber + " " + so.Source_AutonomousSystemOrganization
		bancom["cn"] = so.Source_Country
		bancom["bancount"] = fmt.Sprintf("%d", nbSo)
		bancom["scenario"] = so.Scenario
		bancom["events_count"] = fmt.Sprintf("%d", evtCount)
		bancom["action"] = ba.MeasureType
		bancom["source"] = ba.MeasureSource
		bancom["until"] = time.Until(ba.Until).Round(time.Second).String()
		bancom["reason"] = so.Scenario
		rets = append(rets, bancom)
	}
	return rets, nil
}
