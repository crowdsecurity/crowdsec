package database

import (
	"fmt"
	"sync/atomic"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

//we simply append the event to the transaction
func (c *Context) WriteBanApplication(ban types.BanApplication) error {
	atomic.AddInt32(&c.count, 1)

	c.lock.Lock()
	defer c.lock.Unlock()
	log.Debugf("Ban application being called : %s %s", ban.Scenario, ban.IpText)
	ret := c.Db.Where(types.BanApplication{IpText: ban.IpText}).Assign(types.BanApplication{Until: ban.Until}).Assign(types.BanApplication{Reason: ban.Reason}).Assign(types.BanApplication{MeasureType: ban.MeasureType}).FirstOrCreate(&ban)
	if ret.Error != nil {
		return fmt.Errorf("failed to write ban record : %v", ret.Error)
	}
	return nil
}

func (c *Context) WriteSignal(sig types.SignalOccurence) error {
	atomic.AddInt32(&c.count, 1)
	c.lock.Lock()
	defer c.lock.Unlock()
	/*let's ensure we only have one ban active for a given scope*/
	for _, ba := range sig.BanApplications {
		ret := c.Db.Unscoped().Where("ip_text = ?", ba.IpText).Delete(types.BanApplication{})
		if ret.Error != nil {
			log.Errorf("While delete overlaping bans : %s", ret.Error)
			return fmt.Errorf("failed to write signal occurrence : %v", ret.Error)
		}
	}
	/*and add the new one(s)*/
	ret := c.Db.Create(&sig)
	if ret.Error != nil {
		log.Errorf("While creating new bans : %s", ret.Error)
		return fmt.Errorf("failed to write signal occurrence : %s", ret.Error)
	}

	return nil
}
