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

func NewBlackhole(g *BucketFactory) (*Blackhole, error) {

	var duration time.Duration
	if d, err := time.ParseDuration(g.Blackhole); err != nil {
		g.logger.Warning("Blackhole duration not valid, using 1h")
		return nil, fmt.Errorf("blackhole duration not valid '%s'", g.Blackhole)
	} else {
		duration = d
	}
	return &Blackhole{
		duration:      duration,
		hiddenKeys:    []HiddenKey{},
		DumbProcessor: DumbProcessor{},
	}, nil
}

func (bl *Blackhole) OnBucketOverflow(b *BucketFactory) func(*Leaky, types.Alert, *Queue) (types.Alert, *Queue) {
	return func(l *Leaky, s types.Alert, q *Queue) (types.Alert, *Queue) {
		var blackholed bool = false
		var tmp []HiddenKey
		// search if we are blackholed and refresh the slice
		for _, element := range bl.hiddenKeys {

			if element.key == l.Mapkey {
				if element.expiration.After(l.Ovflw_ts) {
					l.logger.Debugf("Overflow discarded, still blackholed for %s", element.expiration.Sub(l.Ovflw_ts))
					blackholed = true
				}
			}

			if element.expiration.After(l.Ovflw_ts) {
				tmp = append(tmp, element)
			} else {
				l.logger.Debugf("%s left blackhole %s ago", element.key, l.Ovflw_ts.Sub(element.expiration))

			}
		}
		bl.hiddenKeys = tmp

		if blackholed {
			l.logger.Tracef("Event is blackholed (%s)", l.First_ts)
			return types.Alert{
				Mapkey: l.Mapkey,
				// BucketConfiguration: bcfg,
			}, nil
		}
		bl.hiddenKeys = append(bl.hiddenKeys, HiddenKey{l.Mapkey, l.Ovflw_ts.Add(bl.duration)})
		l.logger.Debugf("Adding overflow to blackhole (%s)", l.First_ts)
		return s, q
	}

}
