package csplugin

import (
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
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
	for name := range alertsByPluginName {
		pw.AlertCountByPluginName.Set(name, 0)
	}
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
	var watchTime time.Duration
	var watchCount int = -1
	// Threshold can be set : by time, by count, or both
	// if only time is set, honor it
	// if only count is set, put timer to 1 second and just check size
	// if both are set, set timer to 1 second, but check size && time
	interval := pw.PluginConfigByName[pluginName].GroupWait
	threshold := pw.PluginConfigByName[pluginName].GroupThreshold

	//only size is set
	if threshold > 0 && interval == 0 {
		watchCount = threshold
		watchTime = DefaultEmptyTicker
	} else if interval != 0 && threshold == 0 {
		//only time is set
		watchTime = interval
	} else if interval != 0 && threshold != 0 {
		//both are set
		watchTime = DefaultEmptyTicker
		watchCount = threshold
	} else {
		//none are set, we sent every event we receive
		watchTime = DefaultEmptyTicker
		watchCount = 1
	}

	ticker := time.NewTicker(watchTime)
	var lastSend time.Time = time.Now()
	for {
		select {
		case <-ticker.C:
			send := false
			//if count threshold was set, honor no matter what
			if pc, _ := pw.AlertCountByPluginName.Get(pluginName); watchCount > 0 && pc >= watchCount {
				log.Tracef("[%s] %d alerts received, sending\n", pluginName, pc)
				send = true
				pw.AlertCountByPluginName.Set(pluginName, 0)
			}
			//if time threshold only was set
			if watchTime > 0 && watchTime == interval {
				log.Tracef("sending alerts to %s, duration %s elapsed", pluginName, interval)
				send = true
			}

			//if we hit timer because it was set low to honor count, check if we should trigger
			if watchTime == DefaultEmptyTicker && watchTime != interval && interval != 0 {
				if lastSend.Add(interval).Before(time.Now()) {
					log.Tracef("sending alerts to %s, duration %s elapsed", pluginName, interval)
					send = true
					lastSend = time.Now()
				}
			}
			if send {
				log.Tracef("sending alerts to %s", pluginName)
				pw.PluginEvents <- pluginName
			}
		case <-pw.tomb.Dying():
			ticker.Stop()
			// emptying
			// no lock here because we have the broker still listening even in dying state before killing us
			pw.PluginEvents <- pluginName
			return
		}
	}
}

func (pw *PluginWatcher) watchPluginAlertCounts() {
	for {
		select {
		case pluginName := <-pw.Inserts:
			//we only "count" pending alerts, and watchPluginTicker is actually going to send it
			if _, ok := pw.PluginConfigByName[pluginName]; ok {
				curr, _ := pw.AlertCountByPluginName.Get(pluginName)
				pw.AlertCountByPluginName.Set(pluginName, curr+1)
			}
		case <-pw.tomb.Dying():
			return
		}
	}
}
