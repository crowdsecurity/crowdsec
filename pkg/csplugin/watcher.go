package csplugin

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type PluginWatcher struct {
	PluginConfigByName     map[string]PluginConfig
	AlertCountByPluginName map[string]int
	C                      chan string
	Inserts                chan string
}

func (pw *PluginWatcher) Init(configs map[string]PluginConfig, alertsByPluginName map[string][]*models.Alert) {
	pw.PluginConfigByName = configs
	pw.C = make(chan string)
	pw.AlertCountByPluginName = make(map[string]int)
	pw.Inserts = make(chan string)
	for name := range alertsByPluginName {
		pw.AlertCountByPluginName[name] = 0
	}
}

func (pw *PluginWatcher) Start() {
	for name := range pw.PluginConfigByName {
		go pw.watchPluginTicker(name)
	}
	go pw.watchPluginAlertCounts()
}

func (pw *PluginWatcher) watchPluginTicker(pluginName string) {
	if pw.PluginConfigByName[pluginName].GroupWait <= time.Second*0 {
		return
	}
	ticker := time.NewTicker(pw.PluginConfigByName[pluginName].GroupWait)
	for {
		<-ticker.C
		pw.C <- pluginName
	}
}

func (pw *PluginWatcher) watchPluginAlertCounts() {
	for {
		pluginName := <-pw.Inserts
		if threshold := pw.PluginConfigByName[pluginName].GroupThreshold; threshold < 0 {
			pw.AlertCountByPluginName[pluginName]++
			if pw.AlertCountByPluginName[pluginName] > threshold {
				pw.C <- pluginName
				pw.AlertCountByPluginName[pluginName] = 0
			}
		}
	}
}
