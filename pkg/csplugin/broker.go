package csplugin

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
	plugin "github.com/hashicorp/go-plugin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

var testMode bool = false

const (
	PluginProtocolVersion uint   = 1
	CrowdsecPluginKey     string = "CROWDSEC_PLUGIN_KEY"
)

type PluginBroker struct {
	PluginChannel                   chan ProfileAlert
	alertsByPluginName              map[string][]*models.Alert
	profileConfigs                  []*csconfig.ProfileCfg
	pluginConfigByName              map[string]PluginConfig
	pluginMap                       map[string]plugin.Plugin
	notificationConfigsByPluginType map[string][][]byte // "slack" -> []{config1, config2}
	notificationPluginByName        map[string]Notifier
	watcher                         PluginWatcher
	pluginKillMethods               []func()
}

// holder to determine where to dispatch config and how to format messages
type PluginConfig struct {
	Type           string        `yaml:"type"`
	Name           string        `yaml:"name"`
	GroupWait      time.Duration `yaml:"group_wait"`
	GroupThreshold int           `yaml:"group_threshold"`
	MaxRetry       int           `yaml:"max_retry"`
	TimeOut        time.Duration `yaml:"timeout"`

	Format string `yaml:"format"` // specific to notification plugins

	Config map[string]interface{} `yaml:",inline"` //to keep the plugin-specific config

}

type ProfileAlert struct {
	ProfileID uint
	Alert     *models.Alert
}

func (pb *PluginBroker) Init(profileConfigs []*csconfig.ProfileCfg, configPaths *csconfig.ConfigurationPaths) error {
	pb.PluginChannel = make(chan ProfileAlert)
	pb.notificationConfigsByPluginType = make(map[string][][]byte)
	pb.notificationPluginByName = make(map[string]Notifier)
	pb.pluginMap = make(map[string]plugin.Plugin)
	pb.pluginConfigByName = make(map[string]PluginConfig)
	pb.alertsByPluginName = make(map[string][]*models.Alert)
	pb.profileConfigs = profileConfigs
	if err := pb.loadConfig(configPaths.NotificationDir); err != nil {
		return errors.Wrap(err, "while loading plugin config")
	}
	if err := pb.loadPlugins(configPaths.PluginDir); err != nil {
		return errors.Wrap(err, "while loading plugin")
	}
	pb.watcher = PluginWatcher{}
	pb.watcher.Init(pb.pluginConfigByName, pb.alertsByPluginName)
	return nil

}

func (pb *PluginBroker) Kill() {
	for _, kill := range pb.pluginKillMethods {
		kill()
	}
}

func (pb *PluginBroker) Run(tomb *tomb.Tomb) {
	pb.watcher.Start(tomb)
	log.Infof("%+v", pb.notificationPluginByName)
	for {
		select {
		case profileAlert := <-pb.PluginChannel:
			pb.addProfileAlert(profileAlert)

		case pluginName := <-pb.watcher.PluginEvents:
			// this can be ran in goroutine, but then locks will be needed
			if err := pb.pushNotificationsToPlugin(pluginName); err != nil {
				log.WithField("plugin:", pluginName).Error(err)
			}
			pb.alertsByPluginName[pluginName] = make([]*models.Alert, 0)

		case <-tomb.Dying():
			log.Info("killing all plugins")
			pb.Kill()
			return
		}
	}
}

func (pb *PluginBroker) addProfileAlert(profileAlert ProfileAlert) {
	for _, pluginName := range pb.profileConfigs[profileAlert.ProfileID].Notifications {
		if _, ok := pb.pluginConfigByName[pluginName]; !ok {
			log.Errorf("binary for plugin %s not found.", pluginName)
			continue
		}
		pb.alertsByPluginName[pluginName] = append(pb.alertsByPluginName[pluginName], profileAlert.Alert)
		pb.watcher.Inserts <- pluginName
	}
}
func (pb *PluginBroker) profilesContainPlugin(pluginName string) bool {
	for _, profileCfg := range pb.profileConfigs {
		for _, name := range profileCfg.Notifications {
			if pluginName == name {
				return true
			}
		}
	}
	return false
}
func (pb *PluginBroker) loadConfig(path string) error {
	files, err := listFilesAtPath(path)
	if err != nil {
		return err
	}

	for _, configFilePath := range files {
		yamlFile, err := os.Open(configFilePath)
		if err != nil {
			return errors.Wrapf(err, "while opening %s", configFilePath)
		}
		dec := yaml.NewDecoder(yamlFile)
		for {
			pc := PluginConfig{}
			err = dec.Decode(&pc)
			if err != nil {
				if err == io.EOF {
					break
				}
				return errors.Wrapf(err, "while decoding %s", configFilePath)
			}

			if !pb.profilesContainPlugin(pc.Name) {
				continue
			}

			if pc.MaxRetry == 0 {
				pc.MaxRetry++
			}

			if pc.TimeOut == time.Second*0 {
				pc.TimeOut = time.Second * 5
			}

			if pc.GroupWait == time.Second*0 {
				pc.GroupWait = time.Second * 1
			}
			pb.pluginConfigByName[pc.Name] = pc
		}
	}
	for _, profileCfg := range pb.profileConfigs {
		for _, pluginName := range profileCfg.Notifications {
			if _, ok := pb.pluginConfigByName[pluginName]; !ok {
				return fmt.Errorf("config file for plugin %s not found", pluginName)
			}
		}
	}
	return nil
}

func (pb *PluginBroker) loadPlugins(path string) error {
	binaryPaths, err := listFilesAtPath(path)
	if err != nil {
		return err
	}
	for _, binaryPath := range binaryPaths {
		if !pluginIsValid(binaryPath) {
			log.Errorf("plugin at %s is invalid", binaryPath)
			continue
		}
		pType, pSubtype, err := getPluginTypeAndSubtypeFromPath(binaryPath) // eg pType="notification" , pSubtype="slack"
		if err != nil {
			log.Error(err)
			continue
		}
		if pType != "notification" {
			continue
		}

		pluginClient, err := pb.loadNotificationPlugin(pSubtype, binaryPath)
		if err != nil {
			log.Error(err)
			continue
		}

		for _, pc := range pb.pluginConfigByName {
			if pc.Type != pSubtype {
				continue
			}

			data, err := yaml.Marshal(pc)
			if err != nil {
				log.Error(err)
				continue
			}

			_, err = pluginClient.Configure(context.Background(), &protobufs.Config{Config: data})
			if err != nil {
				log.Error(err)
				continue
			}

			pb.notificationPluginByName[pc.Name] = pluginClient
		}
	}
	return err
}

func (pb *PluginBroker) loadNotificationPlugin(name string, binaryPath string) (Notifier, error) {
	handshake, err := getHandshake()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(binaryPath)
	cmd.SysProcAttr = getProccessAtr()
	pb.pluginMap[name] = &NotifierPlugin{}
	c := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  handshake,
		Plugins:          pb.pluginMap,
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
	pb.pluginKillMethods = append(pb.pluginKillMethods, c.Kill)
	return raw.(Notifier), nil
}

func (pb *PluginBroker) pushNotificationsToPlugin(pluginName string) error {
	if len(pb.alertsByPluginName[pluginName]) == 0 {
		return nil
	}

	message, err := formatAlerts(pb.pluginConfigByName[pluginName].Format, pb.alertsByPluginName[pluginName])
	if err != nil {
		return err
	}
	plugin := pb.notificationPluginByName[pluginName]
	backoffDuration := time.Second
	for i := 1; i <= pb.pluginConfigByName[pluginName].MaxRetry; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), pb.pluginConfigByName[pluginName].TimeOut)
		defer cancel()
		_, err = plugin.Notify(
			ctx,
			&protobufs.Notification{
				Text: message,
				Name: pluginName,
			},
		)
		if err == nil {
			return err
		}
		log.WithField("plugin", pluginName).Errorf("%s error, retry num %d", err.Error(), i)
		time.Sleep(backoffDuration)
		backoffDuration *= 2
	}

	return err
}

func pluginIsValid(path string) bool {
	if testMode {
		return true
	}
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
		log.Errorf("%s is not owned by root user and group", path)
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

func getPluginTypeAndSubtypeFromPath(path string) (string, string, error) {
	pluginFileName := filepath.Base(path)
	parts := strings.Split(pluginFileName, "-")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("plugin name %s is invalid. Name should be like {type-name}", path)
	}
	return strings.Join(parts[:len(parts)-1], "-"), parts[len(parts)-1], nil
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
