package leakybucket

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type hiddenKey struct {
	expiration time.Time
	key        string
}

type blackhole struct {
	duration   time.Duration
	hiddenKeys []hiddenKey
	DumbProcessor
}

func NewBlackhole(bucketFactory *BucketFactory) (*blackhole, error) {
	duration, err := time.ParseDuration(bucketFactory.Blackhole)
	if err != nil {
		return nil, fmt.Errorf("blackhole duration not valid '%s'", bucketFactory.Blackhole)
	}
	return &blackhole{
		duration:      duration,
		hiddenKeys:    []hiddenKey{},
		DumbProcessor: DumbProcessor{},
	}, nil
}

func (bl *blackhole) OnBucketOverflow(_ *BucketFactory, leaky *Leaky, alert pipeline.RuntimeAlert, queue *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue) {
	var blackholed = false
	var tmp []hiddenKey
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
		return pipeline.RuntimeAlert{
			Mapkey: leaky.Mapkey,
		}, nil
	}
	bl.hiddenKeys = append(bl.hiddenKeys, hiddenKey{key:leaky.Mapkey, expiration: leaky.Ovflw_ts.Add(bl.duration)})
	leaky.logger.Debugf("Adding overflow to blackhole (%s)", leaky.First_ts)
	return alert, queue
}
