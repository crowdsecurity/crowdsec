package database

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

/*try to delete entries with matching fields */
func (c *Context) DeleteBan(target string) (int, error) {

	if target != "" {
		ret := c.Db.Delete(types.BanApplication{}, "ip_text = ?", target)
		if ret.Error != nil {
			log.Errorf("Failed to delete record with BanTarget %s : %v", target, ret.Error)
			return 0, ret.Error
		}
		return int(ret.RowsAffected), nil
	}
	return 0, fmt.Errorf("no target provided")
}

func (c *Context) DeleteAll() error {
	allBa := types.BanApplication{}
	records := c.Db.Unscoped().Delete(&allBa)
	if records.Error != nil {
		return records.Error
	}
	return nil
}
