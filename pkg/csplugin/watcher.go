package csplugin

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type PluginWatcher struct {
	PluginConfigByName map[string]PluginConfig
	AlertsByPluginName map[string][]*models.Alert
	C                  chan string
}

func (pw *PluginWatcher) Init(configs map[string]PluginConfig, alerts map[string][]*models.Alert) {
	pw.PluginConfigByName = configs
	pw.AlertsByPluginName = alerts

	pw.C = make(chan string)
}

func (pw *PluginWatcher) Start() {
	for name := range pw.PluginConfigByName {
		pw.watchPlugin(name)
	}
}

func (pw *PluginWatcher) watchPlugin(pluginName string) {
	go pw.watchPluginTicker(pluginName)
	go pw.watchPluginAlerts(pluginName)
}

func (pw *PluginWatcher) watchPluginTicker(pluginName string) {
	ticker := time.NewTicker(pw.PluginConfigByName[pluginName].GroupWait)
	for {
		<-ticker.C
		pw.C <- pluginName
	}
}

func (pw *PluginWatcher) watchPluginAlerts(pluginName string) {
	if pw.PluginConfigByName[pluginName].GroupThreshold <= 0 {
		return
	}

	for {
		time.Sleep(time.Second) // this is for avoiding busy loop and cpu hogging
		pluginLock.Lock()
		if len(pw.AlertsByPluginName[pluginName]) > pw.PluginConfigByName[pluginName].GroupThreshold {
			pw.C <- pluginName
		}
		pluginLock.Unlock()
	}
}
