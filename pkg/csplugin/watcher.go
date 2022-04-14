package csplugin

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"gopkg.in/tomb.v2"
)

/*
 PluginWatcher is here to allow grouping and threshold features for notification plugins :
 by frequency : it will signal the plugin to deliver notifications at this frequence (watchPluginTicker)
 by threshold : it will signal the plugin to deliver notifications when the number of alerts for this plugin reaches this threshold (watchPluginAlertCounts)
*/
type PluginWatcher struct {
	PluginConfigByName     map[string]PluginConfig
	AlertCountByPluginName map[string]int
	PluginEvents           chan string
	Inserts                chan string
	tomb                   *tomb.Tomb
}

func (pw *PluginWatcher) Init(configs map[string]PluginConfig, alertsByPluginName map[string][]*models.Alert) {
	pw.PluginConfigByName = configs
	pw.PluginEvents = make(chan string)
	pw.AlertCountByPluginName = make(map[string]int)
	pw.Inserts = make(chan string)
	for name := range alertsByPluginName {
		pw.AlertCountByPluginName[name] = 0
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
		watchTime = time.Second
	} else if interval != 0 && threshold == 0 {
		//only time is set
		watchTime = interval
	} else if interval != 0 && threshold != 0 {
		//both are set
		watchTime = time.Second
		watchCount = threshold
	} else {
		//none are set, we sent every event we receive
		watchTime = time.Second
		watchCount = 1
	}

	ticker := time.NewTicker(watchTime)
	var lastSend time.Time = time.Now()
	for {
		select {
		case <-ticker.C:
			send := false
			//if count threshold was set, honor no matter what
			if watchCount > 0 && pw.AlertCountByPluginName[pluginName] >= watchCount {
				fmt.Printf("[%s] %d alerts received, sending\n", pluginName, pw.AlertCountByPluginName[pluginName])
				send = true
				pw.AlertCountByPluginName[pluginName] = 0
			} else {
				fmt.Printf("[%s] %d alerts received, NOT sending\n", pluginName, pw.AlertCountByPluginName[pluginName])
			}
			//if time threshold only was set
			if watchTime > 0 && watchTime == interval {
				fmt.Printf("watchTime triggered, sending\n")
				send = true
			}

			//if we hit timer because it was set low to honor count, check if we should trigger
			if watchTime == time.Second && watchTime != interval && interval != 0 {
				fmt.Printf("last send [%s] %s elapsed, required [%s], send %s\n", lastSend, time.Now().Sub(lastSend), interval, pluginName)
				if lastSend.Add(interval).Before(time.Now()) {
					fmt.Printf("SENDING %s, %s elapsed send %s\n", lastSend, time.Now().Sub(lastSend), pluginName)
					send = true
					lastSend = time.Now()
				}
			}
			if send {
				fmt.Printf("SENDING TO %s\n", pluginName)
				pw.PluginEvents <- pluginName
			} else {
				fmt.Printf("skip %s\n", pluginName)
			}
		case <-pw.tomb.Dying():
			ticker.Stop()
			return
		}
	}
}

func (pw *PluginWatcher) watchPluginAlertCounts() {
	for {
		select {
		case pluginName := <-pw.Inserts:
			//we only "count" pending alerts, and watchPluginTicker is actually going to send it
			if threshold := pw.PluginConfigByName[pluginName].GroupThreshold; threshold > 0 {
				pw.AlertCountByPluginName[pluginName]++
			}
		case <-pw.tomb.Dying():
			return
		}
	}
}
