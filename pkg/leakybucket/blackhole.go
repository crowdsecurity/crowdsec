package leakybucket

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
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

func (bl *Blackhole) OnBucketOverflow(bucketFactory *BucketFactory) func(*Leaky, types.RuntimeAlert, *types.Queue) (types.RuntimeAlert, *types.Queue) {
	return func(leaky *Leaky, alert types.RuntimeAlert, queue *types.Queue) (types.RuntimeAlert, *types.Queue) {
		var blackholed = false
		var tmp []HiddenKey
		// search if we are blackholed and refresh the slice
		for _, element := range bl.hiddenKeys {

			if element.key == leaky.Mapkey {
				if element.expiration.After(leaky.Ovflw_ts) {
					leaky.logger.Debugf("Overflow discarded, still blackholed for %s", element.expiration.Sub(leaky.Ovflw_ts))
					blackholed = true
				}
			}

			if element.expiration.After(leaky.Ovflw_ts) {
				tmp = append(tmp, element)
			} else {
				leaky.logger.Debugf("%s left blackhole %s ago", element.key, leaky.Ovflw_ts.Sub(element.expiration))

			}
		}
		bl.hiddenKeys = tmp

		if blackholed {
			leaky.logger.Tracef("Event is blackholed (%s)", leaky.First_ts)
			return types.RuntimeAlert{
				Mapkey: leaky.Mapkey,
			}, nil
		}
		bl.hiddenKeys = append(bl.hiddenKeys, HiddenKey{leaky.Mapkey, leaky.Ovflw_ts.Add(bl.duration)})
		leaky.logger.Debugf("Adding overflow to blackhole (%s)", leaky.First_ts)
		return alert, queue
	}

}
