package database

import (
	"fmt"
	"strconv"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/jinzhu/gorm"
	log "github.com/sirupsen/logrus"
)

type CountResult struct {
	NbTicket int64
	NbEvent  int64
}

//GetBansAt returns the IPs that were banned at a given time
func (c *Context) GetBansAt(at time.Time) ([]map[string]string, error) {
	rets := make([]map[string]string, 0)
	/*get non-expired records*/
	//records := c.Db.Order("updated_at desc").Where("until >= ?", at).Group("ip_text").Find(&bas) /*.Count(&count)*/
	//if records.Error != nil {
	//	return nil, records.Error
	//}

	Sos := []types.SignalOccurence{}
	records := c.Db.Preload("BanApplications", "until >= ?", at).Order("created_at").Preload("BanApplications", func(db *gorm.DB) *gorm.DB {
		return db.Order("until DESC")
	}).Where("deleted_at is NULL").Find(&Sos)
	if records.Error != nil {
		return nil, records.Error
	}
	ret := make(map[string]map[string]string, 0)
	for _, so := range Sos {
		if len(so.BanApplications) == 0 {
			continue
		}
		for _, ba := range so.BanApplications {
			if _, ok := ret[ba.IpText]; !ok {
				ret[ba.IpText] = make(map[string]string, 0)
				ret[ba.IpText]["bancount"] = "0"
				ret[ba.IpText]["events_count"] = "0"
			}
			ret[ba.IpText]["iptext"] = ba.IpText
			ret[ba.IpText]["as"] = so.Source_AutonomousSystemNumber + " " + so.Source_AutonomousSystemOrganization
			ret[ba.IpText]["cn"] = so.Source_Country
			currentBanCount, err := strconv.Atoi(ret[ba.IpText]["bancount"])
			if err != nil {
				log.Errorf("unable to convert bancount '%v' to int :%s", ret[ba.IpText]["bancount"], err)
			}
			ret[ba.IpText]["bancount"] = fmt.Sprintf("%d", currentBanCount+1)
			ret[ba.IpText]["scenario"] = so.Scenario

			ret[ba.IpText]["action"] = ba.MeasureType
			ret[ba.IpText]["source"] = ba.MeasureSource
			ret[ba.IpText]["until"] = time.Until(ba.Until).Round(time.Second).String()
			ret[ba.IpText]["reason"] = so.Scenario
			log.Printf("BA : %+v \n", ba)
		}
		currentEvtCount, err := strconv.Atoi(ret[so.Source_ip]["events_count"])
		if err != nil {
			log.Errorf("unable to convert event_count '%v' to int :%s", ret[so.Source_ip]["events_count"], err)
		}
		ret[so.Source_ip]["events_count"] = fmt.Sprintf("%d", currentEvtCount+so.Events_count)
	}

	for _, ban := range ret {
		rets = append(rets, ban)
	}

	return rets, nil
}

func (c *Context) GetNewBan() ([]types.BanApplication, error) {

	var bas []types.BanApplication

	//select the news bans
	banRecords := c.Db.
		Order("updated_at desc").
		/*Get non expired (until) bans*/
		Where(`until >= ?`, time.Now()).
		/*Only get one ban per unique ip_text*/
		Group("ip_text").
		Find(&bas)
	if banRecords.Error != nil {
		return nil, fmt.Errorf("failed when selection bans : %v", banRecords.Error)
	}

	return bas, nil

}

func (c *Context) GetNewBanSince(since time.Time) ([]types.BanApplication, error) {

	var bas []types.BanApplication

	//select the news bans
	banRecords := c.Db.
		Order("updated_at desc").
		/*Get non expired (until) bans*/
		Where(`until >= ?`, time.Now()).
		/*That were added since last tick*/
		Where(`updated_at >= ?`, since).
		/*Only get one ban per unique ip_text*/
		Group("ip_text").
		Find(&bas) /*.Count(&count)*/
	if banRecords.Error != nil {
		return nil, fmt.Errorf("failed when selection bans : %v", banRecords.Error)
	}

	return bas, nil

}

func (c *Context) GetDeletedBanSince(since time.Time) ([]types.BanApplication, error) {
	var bas []types.BanApplication

	deletedRecords := c.Db.
		/*ignore the soft delete*/
		Unscoped().
		Order("updated_at desc").
		/*ban that were deleted since since or bans that expired since since*/
		Where(`deleted_at >= ? OR 
		   (until >= ? AND until <= ?)`,
			since.Add(1*time.Second), since.Add(1*time.Second), time.Now()).
		/*Only get one ban per unique ip_text*/
		Group("ip_text").
		Find(&bas) /*.Count(&count)*/

	if deletedRecords.Error != nil {
		return nil, fmt.Errorf("failed when selection deleted bans : %v", deletedRecords.Error)
	}

	return bas, nil
}
