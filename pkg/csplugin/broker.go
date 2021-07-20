package csplugin

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
	plugin "github.com/hashicorp/go-plugin"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var pluginLock sync.Mutex

const (
	PluginProtocolVersion uint   = 1
	CrowdsecPluginKey     string = "CROWDSEC_PLUGIN_KEY"
)

type PluginBroker struct {
	AlertsByPluginName              map[string][]*models.Alert
	ProfileConfigs                  []*csconfig.ProfileCfg
	PluginChannel                   chan ProfileAlert
	PluginConfigByName              map[string]PluginConfig
	PluginPaths                     []string
	PluginMap                       map[string]plugin.Plugin
	NotificationConfigsByPluginType map[string][][]byte // "slack" -> []{config1, config2}
	NotificationPluginByName        map[string]Notifier
	Ticker                          PluginWatcher
	PluginKillMethods               []func()
}

// holder to determine where to dispatch config and how to format messages
type PluginConfig struct {
	Type           string        `yaml:"type"`
	Name           string        `yaml:"name"`
	GroupWait      time.Duration `yaml:"group_wait"`
	GroupThreshold int           `yaml:"group_threshold"`

	Format string `yaml:"format"` // specific to notification plugins
}

type ProfileAlert struct {
	ProfileID uint
	Alert     *models.Alert
}

type PluginWatcher struct {
	PluginConfigByName map[string]PluginConfig
	TickerByPluginName map[string]*time.Ticker
	AlertsByPluginName map[string][]*models.Alert
	C                  chan string
}

func (mpt *PluginWatcher) Start() {
	mpt.TickerByPluginName = make(map[string]*time.Ticker)
	mpt.C = make(chan string)
	for name, cfg := range mpt.PluginConfigByName {
		ticker := time.NewTicker(cfg.GroupWait)
		mpt.TickerByPluginName[name] = ticker
	}

	for name, cfg := range mpt.PluginConfigByName {
		go func(name string) {
			for {
				<-mpt.TickerByPluginName[name].C
				mpt.C <- name
			}
		}(name)

		if cfg.GroupThreshold == 0 {
			continue
		}

		go func(name string, cfg PluginConfig) {
			for {
				time.Sleep(time.Second)
				pluginLock.Lock()
				if len(mpt.AlertsByPluginName[name]) > cfg.GroupThreshold {
					mpt.C <- name
				}
				pluginLock.Unlock()
			}
		}(name, cfg)
	}

}

func (pb *PluginBroker) Init(profileConfigs []*csconfig.ProfileCfg, configPaths *csconfig.ConfigurationPaths) error {
	pb.PluginChannel = make(chan ProfileAlert)
	pb.NotificationConfigsByPluginType = make(map[string][][]byte)
	pb.NotificationPluginByName = make(map[string]Notifier)
	pb.PluginMap = make(map[string]plugin.Plugin)
	pb.PluginConfigByName = make(map[string]PluginConfig)
	pb.AlertsByPluginName = make(map[string][]*models.Alert)
	pb.ProfileConfigs = profileConfigs
	if err := pb.LoadConfig(configPaths.NotificationDir); err != nil {
		return err
	}
	err := pb.LoadPlugins(configPaths.PluginDir)
	pb.Ticker = PluginWatcher{PluginConfigByName: pb.PluginConfigByName, AlertsByPluginName: pb.AlertsByPluginName}
	return err
}

func (pb *PluginBroker) LoadConfig(path string) error {
	files, err := listFilesAtPath(path)
	if err != nil {
		return err
	}
	for _, configFile := range files {
		pc := PluginConfig{}
		data, err := os.ReadFile(configFile)
		if err != nil {
			return err
		}
		err = yaml.Unmarshal(data, &pc)
		if err != nil {
			return err
		}
		pb.NotificationConfigsByPluginType[pc.Type] = append(pb.NotificationConfigsByPluginType[pc.Type], data)
	}
	return nil
}

func (pb *PluginBroker) LoadPlugins(path string) error {
	binaryPaths, err := listFilesAtPath(path)
	if err != nil {
		return err
	}
	for _, binaryPath := range binaryPaths {
		if !pluginIsValid(binaryPath) {
			log.Errorf("plugin at %s is invalid", binaryPath)
			continue
		}
		name, Type, err := getPluginNameAndTypeFromPath(binaryPath)
		if err != nil {
			log.Error(err)
			continue
		}
		if Type == "notification" {
			pluginClient, err := pb.LoadNotificationPlugin(name, binaryPath)
			if err != nil {
				log.Error(err)
				continue
			}

			for _, config := range pb.NotificationConfigsByPluginType[name] {
				pc := PluginConfig{}
				err = yaml.Unmarshal(config, &pc)
				if err != nil {
					log.Error(err)
					continue
				}

				pb.PluginConfigByName[pc.Name] = pc
				pb.NotificationPluginByName[pc.Name] = pluginClient
				pluginClient.Configure(context.Background(), &protobufs.Config{Config: config})
			}
		}
	}
	return err
}

func (pb *PluginBroker) LoadNotificationPlugin(name string, binaryPath string) (Notifier, error) {
	handshake, err := getHandshake()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(binaryPath)
	cmd.SysProcAttr = getProccessAtr()
	pb.PluginMap[name] = &NotifierPlugin{}
	c := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  handshake,
		Plugins:          pb.PluginMap,
		Cmd:              cmd,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
	})
	client, err := c.Client()
	if err != nil {
		return nil, err
	}
	raw, err := client.Dispense(name)
	if err != nil {
		return nil, err
	}
	pb.PluginKillMethods = append(pb.PluginKillMethods, c.Kill)
	return raw.(Notifier), nil
}

func (pb *PluginBroker) KillPlugins() {
	for _, kill := range pb.PluginKillMethods {
		kill()
	}
}

func (pb *PluginBroker) PushNotificationsToPlugin(pluginName string) error {
	pluginLock.Lock()
	defer pluginLock.Unlock()
	message, err := formatAlerts(pb.PluginConfigByName[pluginName].Format, pb.AlertsByPluginName[pluginName])
	if err != nil {
		return err
	}
	log.Infof("%d total alerts", len(pb.AlertsByPluginName[pluginName]))
	plugin := pb.NotificationPluginByName[pluginName]
	_, err = plugin.Notify(
		context.Background(),
		&protobufs.Notification{
			Text: message,
			Name: pluginName,
		},
	)
	if err != nil {
		return err
	}
	pb.AlertsByPluginName[pluginName] = make([]*models.Alert, 0)
	return nil
}
func (pb *PluginBroker) Run() {
	go pb.Ticker.Start()
	for {
		select {
		case profileAlert := <-pb.PluginChannel:
			go func() {
				pluginLock.Lock()
				defer pluginLock.Unlock()
				for _, pluginName := range pb.ProfileConfigs[profileAlert.ProfileID].Notifications {
					if _, ok := pb.PluginConfigByName[pluginName]; !ok {
						log.Errorf("binary for notification plugin %s  not found in", pluginName)
						continue
					}
					pb.AlertsByPluginName[pluginName] = append(pb.AlertsByPluginName[pluginName], profileAlert.Alert)
				}
			}()

		case pluginName := <-pb.Ticker.C:
			go func() {
				if len(pb.AlertsByPluginName[pluginName]) == 0 {
					return
				}
				if err := pb.PushNotificationsToPlugin(pluginName); err != nil {
					log.Error(err)
				}
			}()
		}
	}
}

func pluginIsValid(path string) bool {
	var details fs.FileInfo
	var err error

	// check if it exists
	if details, err = os.Stat(path); err != nil {
		log.Error(err)
		return false
	}

	// check if it is owned by root
	stat := details.Sys().(*syscall.Stat_t)
	if stat.Uid != 0 || stat.Gid != 0 {
		log.Errorf("%s is not owned by root user and group")
		return false
	}

	// check if it is world writable
	return (int(details.Mode()) & 2) == 0
}

// helper which gives paths to all files in the given directory non-recursively
func listFilesAtPath(path string) ([]string, error) {
	filePaths := make([]string, 0)
	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		filePaths = append(filePaths, filepath.Join(path, file.Name()))
	}
	return filePaths, nil
}

func getPluginNameAndTypeFromPath(path string) (string, string, error) {
	pluginFileName := filepath.Base(path)
	parts := strings.Split(pluginFileName, "-")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("plugin name %s is invalid. Name should be like {type-name}", path)
	}
	return parts[len(parts)-1], strings.Join(parts[:len(parts)-1], "-"), nil
}

func getProccessAtr() *syscall.SysProcAttr {
	u, _ := user.Lookup("nobody")
	g, _ := user.LookupGroup("nogroup")
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(g.Gid)

	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}
}

func getUUID() (string, error) {
	if d, err := os.ReadFile("/proc/sys/kernel/random/uuid"); err != nil {
		return "", err
	} else {
		return string(d), nil
	}
}

func getHandshake() (plugin.HandshakeConfig, error) {
	uuid, err := getUUID()
	if err != nil {
		return plugin.HandshakeConfig{}, err
	}
	handshake := plugin.HandshakeConfig{
		ProtocolVersion:  PluginProtocolVersion,
		MagicCookieKey:   CrowdsecPluginKey,
		MagicCookieValue: uuid,
	}
	return handshake, nil
}

func formatAlerts(format string, alerts []*models.Alert) (string, error) {
	template, err := template.New("").Parse(format)
	if err != nil {
		return "", err
	}
	b := new(strings.Builder)
	err = template.Execute(b, alerts)
	if err != nil {
		return "", err
	}
	return b.String(), nil
}
