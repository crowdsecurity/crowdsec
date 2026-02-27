package csplugin

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

/*
 PluginWatcher is here to allow grouping and threshold features for notification plugins :
 by frequency : it will signal the plugin to deliver notifications at this frequency (watchPluginTicker)
 by threshold : it will signal the plugin to deliver notifications when the number of alerts for this plugin reaches this threshold (watchPluginAlertCounts)
*/

// TODO: When we start using go 1.18, consider moving this struct in some utils pkg. Make the implementation more generic using generics :)
type alertCounterByPluginName struct {
	sync.Mutex
	data map[string]int
}

func newAlertCounterByPluginName() alertCounterByPluginName {
	return alertCounterByPluginName{
		data: make(map[string]int),
	}
}

func (acp *alertCounterByPluginName) Init() {
	acp.data = make(map[string]int)
}

func (acp *alertCounterByPluginName) Get(key string) (int, bool) {
	acp.Lock()
	val, ok := acp.data[key]
	acp.Unlock()
	return val, ok
}

func (acp *alertCounterByPluginName) Set(key string, val int) {
	acp.Lock()
	acp.data[key] = val
	acp.Unlock()
}

func (acp *alertCounterByPluginName) Inc(key string) {
	acp.Lock()
	acp.data[key]++
	acp.Unlock()
}
type PluginWatcher struct {
	PluginConfigByName     map[string]PluginConfig
	AlertCountByPluginName alertCounterByPluginName
	PluginEvents           chan string
	Inserts                chan string
	tomb                   *tomb.Tomb
}

var DefaultEmptyTicker = time.Second * 1

func (pw *PluginWatcher) Init(configs map[string]PluginConfig, alertsByPluginName map[string][]*models.Alert) {
	pw.PluginConfigByName = configs
	pw.PluginEvents = make(chan string)
	pw.AlertCountByPluginName = newAlertCounterByPluginName()
	pw.Inserts = make(chan string)
}

func (pw *PluginWatcher) Start(tomb *tomb.Tomb) {
	pw.tomb = tomb
	for name := range pw.PluginConfigByName {
		pname := name
		pw.tomb.Go(func() error {
			pw.watchPluginTicker(pname)
			return nil
		})
	}

	pw.tomb.Go(func() error {
		pw.watchPluginAlertCounts()
		return nil
	})
}

func (pw *PluginWatcher) watchPluginTicker(pluginName string) {
	cfg := pw.PluginConfigByName[pluginName]
	interval := cfg.GroupWait
	threshold := cfg.GroupThreshold

	// Alert flush (notification) can be triggered: by interval, by threshold (alert count), or both
	//
	// if only interval is set:
	//  - check with tick=interval
	//  - flush at every tick (if there's anything to notify, ofc)
	//
	// if only threshold is set:
	//  - check with tick=1 second
	//  - flush if threshold is met
	//
	// if both are set:
	//  - check with tick=1 second
	//  - flush on either threshold met or interval elapsed

	tick := DefaultEmptyTicker
	if interval != 0 && threshold == 0 {
		tick = interval
	}

	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	lastSend := time.Now()

	for {
		select {
		case <-ticker.C:
			pc, _ := pw.AlertCountByPluginName.Get(pluginName)
			if pc == 0 {
				// don't send empty notification
				continue
			}

			now := time.Now()

			// See whether to flush, and why

			noneConfigure := interval == 0 && threshold == 0
			byCount := threshold > 0 && pc >= threshold
			byTime := interval != 0 && now.Sub(lastSend) >= interval

			if !noneConfigure && !byCount && !byTime {
				continue
			}

			if byCount {
				log.Tracef("[%s] %d alerts received, sending\n", pluginName, pc)
			} else if byTime {
				log.Tracef("sending alerts to %s, duration %s elapsed", pluginName, interval)
			} else {
				log.Tracef("sending alerts to %s", pluginName)
			}

			lastSend = now
			pw.AlertCountByPluginName.Set(pluginName, 0)
			pw.PluginEvents <- pluginName
		case <-pw.tomb.Dying():
			// no lock here because we have the broker still listening even in dying state before killing us
			select {
			case pw.PluginEvents <- pluginName:
			default: // prevent deadlock during shutdown
			}
			return
		}
	}
}

func (pw *PluginWatcher) watchPluginAlertCounts() {
	for {
		select {
		case pluginName := <-pw.Inserts:
			// we only "count" pending alerts, and watchPluginTicker is actually going to send it
			if _, ok := pw.PluginConfigByName[pluginName]; ok {
				// atomic increment, prevent race between Get/Set
				pw.AlertCountByPluginName.Inc(pluginName)
			}
		case <-pw.tomb.Dying():
			return
		}
	}
}
