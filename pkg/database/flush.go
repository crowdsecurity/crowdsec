package database

import (
	"fmt"
	"time"

	"github.com/go-co-op/gocron"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/bouncer"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/event"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)


func (c *Client) StartFlushScheduler(config *csconfig.FlushDBCfg) (*gocron.Scheduler, error) {
	maxItems := 0
	maxAge := ""
	if config.MaxItems != nil && *config.MaxItems <= 0 {
		return nil, fmt.Errorf("max_items can't be zero or negative number")
	}
	if config.MaxItems != nil {
		maxItems = *config.MaxItems
	}
	if config.MaxAge != nil && *config.MaxAge != "" {
		maxAge = *config.MaxAge
	}

	// Init & Start cronjob every minute for alerts
	scheduler := gocron.NewScheduler(time.UTC)
	job, err := scheduler.Every(1).Minute().Do(c.FlushAlerts, maxAge, maxItems)
	if err != nil {
		return nil, fmt.Errorf("while starting FlushAlerts scheduler: %w", err)
	}

	job.SingletonMode()
	// Init & Start cronjob every hour for bouncers/agents
	if config.AgentsGC != nil {
		if config.AgentsGC.Cert != nil {
			duration, err := ParseDuration(*config.AgentsGC.Cert)
			if err != nil {
				return nil, fmt.Errorf("while parsing agents cert auto-delete duration: %w", err)
			}
			config.AgentsGC.CertDuration = &duration
		}
		if config.AgentsGC.LoginPassword != nil {
			duration, err := ParseDuration(*config.AgentsGC.LoginPassword)
			if err != nil {
				return nil, fmt.Errorf("while parsing agents login/password auto-delete duration: %w", err)
			}
			config.AgentsGC.LoginPasswordDuration = &duration
		}
		if config.AgentsGC.Api != nil {
			log.Warning("agents auto-delete for API auth is not supported (use cert or login_password)")
		}
	}
	if config.BouncersGC != nil {
		if config.BouncersGC.Cert != nil {
			duration, err := ParseDuration(*config.BouncersGC.Cert)
			if err != nil {
				return nil, fmt.Errorf("while parsing bouncers cert auto-delete duration: %w", err)
			}
			config.BouncersGC.CertDuration = &duration
		}
		if config.BouncersGC.Api != nil {
			duration, err := ParseDuration(*config.BouncersGC.Api)
			if err != nil {
				return nil, fmt.Errorf("while parsing bouncers api auto-delete duration: %w", err)
			}
			config.BouncersGC.ApiDuration = &duration
		}
		if config.BouncersGC.LoginPassword != nil {
			log.Warning("bouncers auto-delete for login/password auth is not supported (use cert or api)")
		}
	}
	baJob, err := scheduler.Every(1).Minute().Do(c.FlushAgentsAndBouncers, config.AgentsGC, config.BouncersGC)
	if err != nil {
		return nil, fmt.Errorf("while starting FlushAgentsAndBouncers scheduler: %w", err)
	}

	baJob.SingletonMode()
	scheduler.StartAsync()

	return scheduler, nil
}


func (c *Client) FlushOrphans() {
	/* While it has only been linked to some very corner-case bug : https://github.com/crowdsecurity/crowdsec/issues/778 */
	/* We want to take care of orphaned events for which the parent alert/decision has been deleted */
	eventsCount, err := c.Ent.Event.Delete().Where(event.Not(event.HasOwner())).Exec(c.CTX)
	if err != nil {
		c.Log.Warningf("error while deleting orphan events: %s", err)
		return
	}
	if eventsCount > 0 {
		c.Log.Infof("%d deleted orphan events", eventsCount)
	}

	eventsCount, err = c.Ent.Decision.Delete().Where(
		decision.Not(decision.HasOwner())).Where(decision.UntilLTE(time.Now().UTC())).Exec(c.CTX)

	if err != nil {
		c.Log.Warningf("error while deleting orphan decisions: %s", err)
		return
	}
	if eventsCount > 0 {
		c.Log.Infof("%d deleted orphan decisions", eventsCount)
	}
}

func (c *Client) flushBouncers(bouncersCfg *csconfig.AuthGCCfg) {
	if bouncersCfg == nil {
		return
	}

	if bouncersCfg.ApiDuration != nil {
		log.Debug("trying to delete old bouncers from api")

		deletionCount, err := c.Ent.Bouncer.Delete().Where(
			bouncer.LastPullLTE(time.Now().UTC().Add(-*bouncersCfg.ApiDuration)),
		).Where(
			bouncer.AuthTypeEQ(types.ApiKeyAuthType),
		).Exec(c.CTX)
		if err != nil {
			c.Log.Errorf("while auto-deleting expired bouncers (api key): %s", err)
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
			c.Log.Errorf("while auto-deleting expired bouncers (api key): %s", err)
		} else if deletionCount > 0 {
			c.Log.Infof("deleted %d expired bouncers (api auth)", deletionCount)
		}
	}
}

func (c *Client) flushAgents(agentsCfg *csconfig.AuthGCCfg) {
	if agentsCfg == nil {
		return
	}

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
			c.Log.Errorf("while auto-deleting expired machine (cert): %s", err)
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
			c.Log.Errorf("while auto-deleting expired machine (password): %s", err)
		} else if deletionCount > 0 {
			c.Log.Infof("deleted %d expired machine (password auth)", deletionCount)
		}
	}
}

func (c *Client) FlushAgentsAndBouncers(agentsCfg *csconfig.AuthGCCfg, bouncersCfg *csconfig.AuthGCCfg) error {
	log.Debug("starting FlushAgentsAndBouncers")

	c.flushBouncers(bouncersCfg)
	c.flushAgents(agentsCfg)

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
		c.Log.Warningf("FlushAlerts (max items count): %s", err)
		return fmt.Errorf("unable to get alerts count: %w", err)
	}

	c.Log.Debugf("FlushAlerts (Total alerts): %d", totalAlerts)
	if MaxAge != "" {
		filter := map[string][]string{
			"created_before": {MaxAge},
		}
		nbDeleted, err := c.DeleteAlertWithFilter(filter)
		if err != nil {
			c.Log.Warningf("FlushAlerts (max age): %s", err)
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
					c.Log.Errorf("FlushAlerts: Could not delete alerts: %s", err)
					return fmt.Errorf("could not delete alerts: %w", err)
				}
			}
		}
	}
	if deletedByNbItem > 0 {
		c.Log.Infof("flushed %d/%d alerts because the max number of alerts has been reached (%d max)", deletedByNbItem, totalAlerts, MaxItems)
	}
	if deletedByAge > 0 {
		c.Log.Infof("flushed %d/%d alerts because they were created %s ago or more", deletedByAge, totalAlerts, MaxAge)
	}
	return nil
}
