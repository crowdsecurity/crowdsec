package sqlite

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
	ret := c.tx.Where(types.BanApplication{IpText: ban.IpText}).Assign(types.BanApplication{Until: ban.Until}).Assign(types.BanApplication{Reason: ban.Reason}).Assign(types.BanApplication{MeasureType: ban.MeasureType}).FirstOrCreate(&ban)
	if ret.Error != nil {
		return fmt.Errorf("failed to write ban record : %v", ret.Error)
	}
	return nil
}

func (c *Context) WriteSignal(sig types.SignalOccurence) error {
	atomic.AddInt32(&c.count, 1)
	c.lock.Lock()
	defer c.lock.Unlock()
	//log.Debugf("Ban signal being called : %s %s", sig.Scenario, sig.Source.Ip.String())
	ret := c.tx.Create(&sig)
	//sig.Scenario = sig.Scenario
	if ret.Error != nil {
		log.Errorf("FAILED : %+v \n", ret.Error)
		return fmt.Errorf("failed to write signal occurence : %v", ret.Error)
	}
	return nil
}
