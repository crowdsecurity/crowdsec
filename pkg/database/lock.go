package database

import (
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/lock"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	CAPIPullLockTimeout = 120
	MetricsLockTimeout  = 30
)

func (c *Client) AcquireLock(name string) error {
	// pessimistic lock
	_, err := c.Ent.Lock.Create().
		SetName(name).
		SetCreatedAt(types.UtcNow()).
		Save(c.CTX)
	if ent.IsConstraintError(err) {
		return err
	}
	if err != nil {
		return errors.Wrapf(InsertFail, "insert lock: %s", err)
	}
	return nil
}

func (c *Client) ReleaseLock(name string) error {
	_, err := c.Ent.Lock.Delete().Where(lock.NameEQ(name)).Exec(c.CTX)
	if err != nil {
		return errors.Wrapf(DeleteFail, "delete lock: %s", err)
	}
	return nil
}

func (c *Client) ReleaseLockWithTimeout(name string, timeout int) error {
	log.Debugf("(%s) releasing orphin locks", name)
	_, err := c.Ent.Lock.Delete().Where(
		lock.NameEQ(name),
		lock.CreatedAtLT(time.Now().Add(-time.Duration(timeout)*time.Minute)),
	).Exec(c.CTX)
	if err != nil {
		return errors.Wrapf(DeleteFail, "delete lock: %s", err)
	}
	return nil
}

func (c *Client) IsLocked(err error) bool {
	return ent.IsConstraintError(err)
}

func (c *Client) AcquirePushMetricsLock() error {
	lockName := "pushMetrics"
	err := c.ReleaseLockWithTimeout(lockName, MetricsLockTimeout)
	if err != nil {
		log.Errorf("unable to release pushMetrics lock: %s", err)
	}
	return c.AcquireLock(lockName)
}

func (c *Client) ReleasePushMetricsLock() error {
	return c.ReleaseLock("pushMetrics")
}

func (c *Client) AcquirePullCAPILock() error {
	lockName := "pullCAPI"
	err := c.ReleaseLockWithTimeout(lockName, CAPIPullLockTimeout)
	if err != nil {
		log.Errorf("unable to release pullCAPI lock: %s", err)
	}
	return c.AcquireLock(lockName)
}

func (c *Client) ReleasePullCAPILock() error {
	return c.ReleaseLockWithTimeout("pullCAPI", CAPIPullLockTimeout)
}
