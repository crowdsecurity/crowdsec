package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-co-op/gocron"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/allowlistitem"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/bouncer"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/event"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/metric"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	// how long to keep metrics in the local database
	defaultMetricsMaxAge = 7 * 24 * time.Hour
	flushInterval        = 1 * time.Minute
)

func (c *Client) StartFlushScheduler(ctx context.Context, config *csconfig.FlushDBCfg) (*gocron.Scheduler, error) {
	maxItems := 0
	maxAge := ""

	if config.MaxItems != nil && *config.MaxItems <= 0 {
		return nil, errors.New("max_items can't be zero or negative")
	}

	if config.MaxItems != nil {
		maxItems = *config.MaxItems
	}

	if config.MaxAge != nil && *config.MaxAge != "" {
		maxAge = *config.MaxAge
	}

	// Init & Start cronjob every minute for alerts
	scheduler := gocron.NewScheduler(time.UTC)

	job, err := scheduler.Every(1).Minute().Do(c.FlushAlerts, ctx, maxAge, maxItems)
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

	baJob, err := scheduler.Every(flushInterval).Do(c.FlushAgentsAndBouncers, ctx, config.AgentsGC, config.BouncersGC)
	if err != nil {
		return nil, fmt.Errorf("while starting FlushAgentsAndBouncers scheduler: %w", err)
	}

	baJob.SingletonMode()

	metricsJob, err := scheduler.Every(flushInterval).Do(c.flushMetrics, ctx, config.MetricsMaxAge)
	if err != nil {
		return nil, fmt.Errorf("while starting flushMetrics scheduler: %w", err)
	}

	metricsJob.SingletonMode()

	allowlistsJob, err := scheduler.Every(flushInterval).Do(c.flushAllowlists, ctx)
	if err != nil {
		return nil, fmt.Errorf("while starting FlushAllowlists scheduler: %w", err)
	}

	allowlistsJob.SingletonMode()

	scheduler.StartAsync()

	return scheduler, nil
}

// flushMetrics deletes metrics older than maxAge, regardless if they have been pushed to CAPI or not
func (c *Client) flushMetrics(ctx context.Context, maxAge *time.Duration) {
	if maxAge == nil {
		maxAge = ptr.Of(defaultMetricsMaxAge)
	}

	c.Log.Debugf("flushing metrics older than %s", maxAge)

	deleted, err := c.Ent.Metric.Delete().Where(
		metric.ReceivedAtLTE(time.Now().UTC().Add(-*maxAge)),
	).Exec(ctx)
	if err != nil {
		c.Log.Errorf("while flushing metrics: %s", err)
		return
	}

	if deleted > 0 {
		c.Log.Debugf("flushed %d metrics snapshots", deleted)
	}
}

func (c *Client) FlushOrphans(ctx context.Context) {
	/* While it has only been linked to some very corner-case bug : https://github.com/crowdsecurity/crowdsec/issues/778 */
	/* We want to take care of orphaned events for which the parent alert/decision has been deleted */
	eventsCount, err := c.Ent.Event.Delete().Where(event.Not(event.HasOwner())).Exec(ctx)
	if err != nil {
		c.Log.Warningf("error while deleting orphan events: %s", err)
		return
	}

	if eventsCount > 0 {
		c.Log.Infof("%d deleted orphan events", eventsCount)
	}

	eventsCount, err = c.Ent.Decision.Delete().Where(
		decision.Not(decision.HasOwner())).Where(decision.UntilLTE(time.Now().UTC())).Exec(ctx)
	if err != nil {
		c.Log.Warningf("error while deleting orphan decisions: %s", err)
		return
	}

	if eventsCount > 0 {
		c.Log.Infof("%d deleted orphan decisions", eventsCount)
	}
}

func (c *Client) flushBouncers(ctx context.Context, authType string, duration *time.Duration) {
	if duration == nil {
		return
	}

	count, err := c.Ent.Bouncer.Delete().Where(
		bouncer.LastPullLTE(time.Now().UTC().Add(-*duration)),
	).Where(
		bouncer.AuthTypeEQ(authType),
	).Exec(ctx)
	if err != nil {
		c.Log.Errorf("while auto-deleting expired bouncers (%s): %s", authType, err)
		return
	}

	if count > 0 {
		c.Log.Infof("deleted %d expired bouncers (%s)", count, authType)
	}
}

func (c *Client) flushAgents(ctx context.Context, authType string, duration *time.Duration) {
	if duration == nil {
		return
	}

	count, err := c.Ent.Machine.Delete().Where(
		machine.LastHeartbeatLTE(time.Now().UTC().Add(-*duration)),
		machine.Not(machine.HasAlerts()),
		machine.AuthTypeEQ(authType),
	).Exec(ctx)
	if err != nil {
		c.Log.Errorf("while auto-deleting expired machines (%s): %s", authType, err)
		return
	}

	if count > 0 {
		c.Log.Infof("deleted %d expired machines (%s auth)", count, authType)
	}
}

func (c *Client) FlushAgentsAndBouncers(ctx context.Context, agentsCfg *csconfig.AuthGCCfg, bouncersCfg *csconfig.AuthGCCfg) error {
	log.Debug("starting FlushAgentsAndBouncers")

	if agentsCfg != nil {
		c.flushAgents(ctx, types.TlsAuthType, agentsCfg.CertDuration)
		c.flushAgents(ctx, types.PasswordAuthType, agentsCfg.LoginPasswordDuration)
	}

	if bouncersCfg != nil {
		c.flushBouncers(ctx, types.TlsAuthType, bouncersCfg.CertDuration)
		c.flushBouncers(ctx, types.ApiKeyAuthType, bouncersCfg.ApiDuration)
	}

	return nil
}

func (c *Client) FlushAlerts(ctx context.Context, maxAge string, maxItems int) error {
	var (
		deletedByAge    int
		deletedByNbItem int
		totalAlerts     int
		err             error
	)

	if !c.CanFlush {
		c.Log.Debug("a list is being imported, flushing later")
		return nil
	}

	c.Log.Debug("Flushing orphan alerts")
	c.FlushOrphans(ctx)
	c.Log.Debug("Done flushing orphan alerts")

	totalAlerts, err = c.TotalAlerts(ctx)
	if err != nil {
		c.Log.Warningf("FlushAlerts (max items count): %s", err)
		return fmt.Errorf("unable to get alerts count: %w", err)
	}

	c.Log.Debugf("FlushAlerts (Total alerts): %d", totalAlerts)

	if maxAge != "" {
		filter := map[string][]string{
			"created_before": {maxAge},
		}

		nbDeleted, err := c.DeleteAlertWithFilter(ctx, filter)
		if err != nil {
			c.Log.Warningf("FlushAlerts (max age): %s", err)
			return fmt.Errorf("unable to flush alerts with filter until=%s: %w", maxAge, err)
		}

		c.Log.Debugf("FlushAlerts (deleted max age alerts): %d", nbDeleted)
		deletedByAge = nbDeleted
	}

	if maxItems > 0 {
		// We get the highest id for the alerts
		// We subtract MaxItems to avoid deleting alerts that are not old enough
		// This gives us the oldest alert that we want to keep
		// We then delete all the alerts with an id lower than this one
		// We can do this because the id is auto-increment, and the database won't reuse the same id twice
		lastAlert, err := c.QueryAlertWithFilter(ctx, map[string][]string{
			"sort":  {"DESC"},
			"limit": {"1"},
			// we do not care about fetching the edges, we just want the id
			"with_decisions": {"false"},
		})
		c.Log.Debugf("FlushAlerts (last alert): %+v", lastAlert)

		if err != nil {
			c.Log.Errorf("FlushAlerts: could not get last alert: %s", err)
			return fmt.Errorf("could not get last alert: %w", err)
		}

		if len(lastAlert) != 0 {
			maxid := lastAlert[0].ID - maxItems

			c.Log.Debugf("FlushAlerts (max id): %d", maxid)

			if maxid > 0 {
				// This may lead to orphan alerts (at least on MySQL), but the next time the flush job will run, they will be deleted
				deletedByNbItem, err = c.Ent.Alert.Delete().Where(alert.IDLT(maxid)).Exec(ctx)
				if err != nil {
					c.Log.Errorf("FlushAlerts: Could not delete alerts: %s", err)
					return fmt.Errorf("could not delete alerts: %w", err)
				}
			}
		}
	}

	if deletedByNbItem > 0 {
		c.Log.Infof("flushed %d/%d alerts because the max number of alerts has been reached (%d max)",
			deletedByNbItem, totalAlerts, maxItems)
	}

	if deletedByAge > 0 {
		c.Log.Infof("flushed %d/%d alerts because they were created %s ago or more",
			deletedByAge, totalAlerts, maxAge)
	}

	return nil
}

func (c *Client) flushAllowlists(ctx context.Context) {
	deleted, err := c.Ent.AllowListItem.Delete().Where(
		allowlistitem.ExpiresAtLTE(time.Now().UTC()),
	).Exec(ctx)
	if err != nil {
		c.Log.Errorf("while flushing allowlists: %s", err)
		return
	}

	if deleted > 0 {
		c.Log.Debugf("flushed %d allowlists", deleted)
	}
}
