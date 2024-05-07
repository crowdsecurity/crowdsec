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
	CAPIPullLockTimeout = 10
	CapiPullLockName    = "pullCAPI"
)

func (c *Client) AcquireLock(name string) error {
	log.Debugf("acquiring lock %s", name)
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
	log.Debugf("releasing lock %s", name)
	_, err := c.Ent.Lock.Delete().Where(lock.NameEQ(name)).Exec(c.CTX)
	if err != nil {
		return errors.Wrapf(DeleteFail, "delete lock: %s", err)
	}
	return nil
}

func (c *Client) ReleaseLockWithTimeout(name string, timeout int) error {
	log.Debugf("releasing lock %s with timeout of %d minutes", name, timeout)
	_, err := c.Ent.Lock.Delete().Where(
		lock.NameEQ(name),
		lock.CreatedAtLT(time.Now().UTC().Add(-time.Duration(timeout)*time.Minute)),
	).Exec(c.CTX)

	if err != nil {
		return errors.Wrapf(DeleteFail, "delete lock: %s", err)
	}
	return nil
}

func (c *Client) IsLocked(err error) bool {
	return ent.IsConstraintError(err)
}

func (c *Client) AcquirePullCAPILock() error {

	/*delete orphan "old" lock if present*/
	err := c.ReleaseLockWithTimeout(CapiPullLockName, CAPIPullLockTimeout)
	if err != nil {
		log.Errorf("unable to release pullCAPI lock: %s", err)
	}
	return c.AcquireLock(CapiPullLockName)
}

func (c *Client) ReleasePullCAPILock() error {
	log.Debugf("deleting lock %s", CapiPullLockName)
	_, err := c.Ent.Lock.Delete().Where(
		lock.NameEQ(CapiPullLockName),
	).Exec(c.CTX)
	if err != nil {
		return errors.Wrapf(DeleteFail, "delete lock: %s", err)
	}
	return nil
}
