package database

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/bouncer"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/event"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func (c *Client) FlushOrphans() {
	/* While it has only been linked to some very corner-case bug : https://github.com/crowdsecurity/crowdsec/issues/778 */
	/* We want to take care of orphaned events for which the parent alert/decision has been deleted */

	events_count, err := c.Ent.Event.Delete().Where(event.Not(event.HasOwner())).Exec(c.CTX)
	if err != nil {
		c.Log.Warningf("error while deleting orphan events : %s", err)
		return
	}
	if events_count > 0 {
		c.Log.Infof("%d deleted orphan events", events_count)
	}

	events_count, err = c.Ent.Decision.Delete().Where(
		decision.Not(decision.HasOwner())).Where(decision.UntilLTE(time.Now().UTC())).Exec(c.CTX)

	if err != nil {
		c.Log.Warningf("error while deleting orphan decisions : %s", err)
		return
	}
	if events_count > 0 {
		c.Log.Infof("%d deleted orphan decisions", events_count)
	}
}

func (c *Client) FlushAgentsAndBouncers(agentsCfg *csconfig.AuthGCCfg, bouncersCfg *csconfig.AuthGCCfg) error {
	log.Debug("starting FlushAgentsAndBouncers")
	if bouncersCfg != nil {
		if bouncersCfg.ApiDuration != nil {
			log.Debug("trying to delete old bouncers from api")
			deletionCount, err := c.Ent.Bouncer.Delete().Where(
				bouncer.LastPullLTE(time.Now().UTC().Add(-*bouncersCfg.ApiDuration)),
			).Where(
				bouncer.AuthTypeEQ(types.ApiKeyAuthType),
			).Exec(c.CTX)
			if err != nil {
				c.Log.Errorf("while auto-deleting expired bouncers (api key) : %s", err)
			} else if deletionCount > 0 {
				c.Log.Infof("deleted %d expired bouncers (api auth)", deletionCount)
			}
		}
		if bouncersCfg.CertDuration != nil {
			log.Debug("trying to delete old bouncers from cert")

			deletionCount, err := c.Ent.Bouncer.Delete().Where(
				bouncer.LastPullLTE(time.Now().UTC().Add(-*bouncersCfg.CertDuration)),
			).Where(
				bouncer.AuthTypeEQ(types.TlsAuthType),
			).Exec(c.CTX)
			if err != nil {
				c.Log.Errorf("while auto-deleting expired bouncers (api key) : %s", err)
			} else if deletionCount > 0 {
				c.Log.Infof("deleted %d expired bouncers (api auth)", deletionCount)
			}
		}
	}

	if agentsCfg != nil {
		if agentsCfg.CertDuration != nil {
			log.Debug("trying to delete old agents from cert")

			deletionCount, err := c.Ent.Machine.Delete().Where(
				machine.LastHeartbeatLTE(time.Now().UTC().Add(-*agentsCfg.CertDuration)),
			).Where(
				machine.Not(machine.HasAlerts()),
			).Where(
				machine.AuthTypeEQ(types.TlsAuthType),
			).Exec(c.CTX)
			log.Debugf("deleted %d entries", deletionCount)
			if err != nil {
				c.Log.Errorf("while auto-deleting expired machine (cert) : %s", err)
			} else if deletionCount > 0 {
				c.Log.Infof("deleted %d expired machine (cert auth)", deletionCount)
			}
		}
		if agentsCfg.LoginPasswordDuration != nil {
			log.Debug("trying to delete old agents from password")

			deletionCount, err := c.Ent.Machine.Delete().Where(
				machine.LastHeartbeatLTE(time.Now().UTC().Add(-*agentsCfg.LoginPasswordDuration)),
			).Where(
				machine.Not(machine.HasAlerts()),
			).Where(
				machine.AuthTypeEQ(types.PasswordAuthType),
			).Exec(c.CTX)
			log.Debugf("deleted %d entries", deletionCount)
			if err != nil {
				c.Log.Errorf("while auto-deleting expired machine (password) : %s", err)
			} else if deletionCount > 0 {
				c.Log.Infof("deleted %d expired machine (password auth)", deletionCount)
			}
		}
	}
	return nil
}

func (c *Client) FlushAlerts(MaxAge string, MaxItems int) error {
	var deletedByAge int
	var deletedByNbItem int
	var totalAlerts int
	var err error

	if !c.CanFlush {
		c.Log.Debug("a list is being imported, flushing later")
		return nil
	}

	c.Log.Debug("Flushing orphan alerts")
	c.FlushOrphans()
	c.Log.Debug("Done flushing orphan alerts")
	totalAlerts, err = c.TotalAlerts()
	if err != nil {
		c.Log.Warningf("FlushAlerts (max items count) : %s", err)
		return fmt.Errorf("unable to get alerts count: %w", err)
	}
	c.Log.Debugf("FlushAlerts (Total alerts): %d", totalAlerts)
	if MaxAge != "" {
		filter := map[string][]string{
			"created_before": {MaxAge},
		}
		nbDeleted, err := c.DeleteAlertWithFilter(filter)
		if err != nil {
			c.Log.Warningf("FlushAlerts (max age) : %s", err)
			return fmt.Errorf("unable to flush alerts with filter until=%s: %w", MaxAge, err)
		}
		c.Log.Debugf("FlushAlerts (deleted max age alerts): %d", nbDeleted)
		deletedByAge = nbDeleted
	}
	if MaxItems > 0 {
		//We get the highest id for the alerts
		//We subtract MaxItems to avoid deleting alerts that are not old enough
		//This gives us the oldest alert that we want to keep
		//We then delete all the alerts with an id lower than this one
		//We can do this because the id is auto-increment, and the database won't reuse the same id twice
		lastAlert, err := c.QueryAlertWithFilter(map[string][]string{
			"sort":  {"DESC"},
			"limit": {"1"},
			//we do not care about fetching the edges, we just want the id
			"with_decisions": {"false"},
		})
		c.Log.Debugf("FlushAlerts (last alert): %+v", lastAlert)
		if err != nil {
			c.Log.Errorf("FlushAlerts: could not get last alert: %s", err)
			return fmt.Errorf("could not get last alert: %w", err)
		}

		if len(lastAlert) != 0 {
			maxid := lastAlert[0].ID - MaxItems

			c.Log.Debugf("FlushAlerts (max id): %d", maxid)

			if maxid > 0 {
				//This may lead to orphan alerts (at least on MySQL), but the next time the flush job will run, they will be deleted
				deletedByNbItem, err = c.Ent.Alert.Delete().Where(alert.IDLT(maxid)).Exec(c.CTX)

				if err != nil {
					c.Log.Errorf("FlushAlerts: Could not delete alerts : %s", err)
					return fmt.Errorf("could not delete alerts: %w", err)
				}
			}
		}
	}
	if deletedByNbItem > 0 {
		c.Log.Infof("flushed %d/%d alerts because max number of alerts has been reached (%d max)", deletedByNbItem, totalAlerts, MaxItems)
	}
	if deletedByAge > 0 {
		c.Log.Infof("flushed %d/%d alerts because they were created %s ago or more", deletedByAge, totalAlerts, MaxAge)
	}
	return nil
}
