package leakybucket

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

type HiddenKey struct {
	key        string
	expiration time.Time
}

type Blackhole struct {
	duration   time.Duration
	hiddenKeys []HiddenKey
	DumbProcessor
}

func NewBlackhole(bucketFactory *BucketFactory) (*Blackhole, error) {
	duration, err := time.ParseDuration(bucketFactory.Blackhole)
	if err != nil {
		bucketFactory.logger.Warning("Blackhole duration not valid, using 1h")
		return nil, fmt.Errorf("blackhole duration not valid '%s'", bucketFactory.Blackhole)
	}
	return &Blackhole{
		duration:      duration,
		hiddenKeys:    []HiddenKey{},
		DumbProcessor: DumbProcessor{},
	}, nil
}

func CleanupBlackhole(bucketsTomb *tomb.Tomb) error {
	ticker := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-bucketsTomb.Dying():
			ticker.Stop()
			BlackholeTracking.Range(func(key, value interface{}) bool {
				BlackholeTracking.Delete(key)
				return true
			})
			return nil
		case <-ticker.C:
			BlackholeTracking.Range(func(key, value interface{}) bool {
				expirationDate := value.(time.Time)
				if expirationDate.Before(time.Now().UTC()) {
					log.Debugf("Expiring blackhole for %s", key)
					BlackholeTracking.Delete(key)
				}
				return true
			})
		}
	}
}

func (bl *Blackhole) OnBucketOverflow(bucketFactory *BucketFactory) func(*Leaky, types.RuntimeAlert, *Queue) (types.RuntimeAlert, *Queue) {
	return func(leaky *Leaky, alert types.RuntimeAlert, queue *Queue) (types.RuntimeAlert, *Queue) {
		if expirationDate, ok := BlackholeTracking.Load(leaky.Mapkey); ok {
			if expirationDate.(time.Time).After(time.Now().UTC()) {
				leaky.logger.Debugf("Blackhole already triggered for %s", leaky.Mapkey)
				return types.RuntimeAlert{
					Mapkey: leaky.Mapkey,
				}, nil
			} else {
				leaky.logger.Debugf("Blackhole expired for %s", leaky.Mapkey)
				BlackholeTracking.Delete(leaky.Mapkey)
			}
		}

		BlackholeTracking.Store(leaky.Mapkey, time.Now().UTC().Add(bl.duration))

		leaky.logger.Debugf("Blackhole triggered for %s", leaky.Mapkey)

		return alert, queue
	}
}
