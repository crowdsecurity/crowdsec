package csplugin

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"gopkg.in/tomb.v2"
)

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
	if pw.PluginConfigByName[pluginName].GroupWait <= time.Second*0 {
		return
	}
	ticker := time.NewTicker(pw.PluginConfigByName[pluginName].GroupWait)
	for {
		select {
		case <-ticker.C:
			pw.PluginEvents <- pluginName

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
			if threshold := pw.PluginConfigByName[pluginName].GroupThreshold; threshold > 0 {
				pw.AlertCountByPluginName[pluginName]++
				if pw.AlertCountByPluginName[pluginName] >= threshold {
					pw.PluginEvents <- pluginName
					pw.AlertCountByPluginName[pluginName] = 0
				}
			}
		case <-pw.tomb.Dying():
			return
		}
	}
}
