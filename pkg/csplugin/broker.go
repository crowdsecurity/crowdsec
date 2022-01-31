package csplugin

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"math"
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

	"github.com/Masterminds/sprig"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	plugin "github.com/hashicorp/go-plugin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

var testMode bool = false
var pluginMutex sync.Mutex

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
	pluginProcConfig                *csconfig.PluginCfg
	pluginsTypesToDispatch          map[string]struct{}
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

func (pb *PluginBroker) Init(pluginCfg *csconfig.PluginCfg, profileConfigs []*csconfig.ProfileCfg, configPaths *csconfig.ConfigurationPaths) error {
	pb.PluginChannel = make(chan ProfileAlert)
	pb.notificationConfigsByPluginType = make(map[string][][]byte)
	pb.notificationPluginByName = make(map[string]Notifier)
	pb.pluginMap = make(map[string]plugin.Plugin)
	pb.pluginConfigByName = make(map[string]PluginConfig)
	pb.alertsByPluginName = make(map[string][]*models.Alert)
	pb.profileConfigs = profileConfigs
	pb.pluginProcConfig = pluginCfg
	pb.pluginsTypesToDispatch = make(map[string]struct{})
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
	for {
		select {
		case profileAlert := <-pb.PluginChannel:
			pb.addProfileAlert(profileAlert)

		case pluginName := <-pb.watcher.PluginEvents:
			// this can be ran in goroutine, but then locks will be needed
			pluginMutex.Lock()
			tmpAlerts := pb.alertsByPluginName[pluginName]
			pb.alertsByPluginName[pluginName] = make([]*models.Alert, 0)
			pluginMutex.Unlock()
			go func() {
				if err := pb.pushNotificationsToPlugin(pluginName, tmpAlerts); err != nil {
					log.WithField("plugin:", pluginName).Error(err)
				}
			}()

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
			log.Errorf("plugin %s is not configured properly.", pluginName)
			continue
		}
		pluginMutex.Lock()
		pb.alertsByPluginName[pluginName] = append(pb.alertsByPluginName[pluginName], profileAlert.Alert)
		pluginMutex.Unlock()
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
		if !strings.HasSuffix(configFilePath, ".yaml") && !strings.HasSuffix(configFilePath, ".yml") {
			continue
		}

		pluginConfigs, err := parsePluginConfigFile(configFilePath)
		if err != nil {
			return err
		}
		for _, pluginConfig := range pluginConfigs {
			if !pb.profilesContainPlugin(pluginConfig.Name) {
				continue
			}
			setRequiredFields(&pluginConfig)
			if _, ok := pb.pluginConfigByName[pluginConfig.Name]; ok {
				log.Warnf("several configs for notification %s found  ", pluginConfig.Name)
			}
			pb.pluginConfigByName[pluginConfig.Name] = pluginConfig
		}
	}
	err = pb.verifyPluginConfigsWithProfile()
	return err
}

func (pb *PluginBroker) verifyPluginConfigsWithProfile() error {
	for _, profileCfg := range pb.profileConfigs {
		for _, pluginName := range profileCfg.Notifications {
			if _, ok := pb.pluginConfigByName[pluginName]; !ok {
				return fmt.Errorf("config file for plugin %s not found", pluginName)
			}
			pb.pluginsTypesToDispatch[pb.pluginConfigByName[pluginName].Type] = struct{}{}
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
		if err := pluginIsValid(binaryPath); err != nil {
			return err
		}
		pType, pSubtype, err := getPluginTypeAndSubtypeFromPath(binaryPath) // eg pType="notification" , pSubtype="slack"
		if err != nil {
			return err
		}
		if pType != "notification" {
			continue
		}

		if _, ok := pb.pluginsTypesToDispatch[pSubtype]; !ok {
			continue
		}

		pluginClient, err := pb.loadNotificationPlugin(pSubtype, binaryPath)
		if err != nil {
			return err
		}
		for _, pc := range pb.pluginConfigByName {
			if pc.Type != pSubtype {
				continue
			}

			data, err := yaml.Marshal(pc)
			if err != nil {
				return err
			}

			_, err = pluginClient.Configure(context.Background(), &protobufs.Config{Config: data})
			if err != nil {
				return errors.Wrapf(err, "while configuring %s", pc.Name)
			}
			log.Infof("registered plugin %s", pc.Name)
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
	cmd.SysProcAttr, err = getProcessAtr(pb.pluginProcConfig.User, pb.pluginProcConfig.Group)
	if err != nil {
		return nil, errors.Wrap(err, "while getting process attributes")
	}
	cmd.SysProcAttr.Credential.NoSetGroups = true
	pb.pluginMap[name] = &NotifierPlugin{}
	l := log.New()
	err = types.ConfigureLogger(l)
	if err != nil {
		return nil, err
	}
	// We set the highest level to permit plugins to set their own log level
	// without that, crowdsec log level is controlling plugins level
	l.SetLevel(log.TraceLevel)
	logger := NewHCLogAdapter(l, "")
	c := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  handshake,
		Plugins:          pb.pluginMap,
		Cmd:              cmd,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Logger:           logger,
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

func (pb *PluginBroker) pushNotificationsToPlugin(pluginName string, alerts []*models.Alert) error {
	if len(alerts) == 0 {
		return nil
	}

	message, err := formatAlerts(pb.pluginConfigByName[pluginName].Format, alerts)
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

func parsePluginConfigFile(path string) ([]PluginConfig, error) {
	parsedConfigs := make([]PluginConfig, 0)
	yamlFile, err := os.Open(path)
	if err != nil {
		return parsedConfigs, errors.Wrapf(err, "while opening %s", path)
	}
	dec := yaml.NewDecoder(yamlFile)
	dec.SetStrict(true)
	for {
		pc := PluginConfig{}
		err = dec.Decode(&pc)
		if err != nil {
			if err == io.EOF {
				break
			}
			return []PluginConfig{}, fmt.Errorf("while decoding %s got error %s", path, err.Error())
		}
		parsedConfigs = append(parsedConfigs, pc)
	}
	return parsedConfigs, nil
}

func setRequiredFields(pluginCfg *PluginConfig) {
	if pluginCfg.MaxRetry == 0 {
		pluginCfg.MaxRetry++
	}

	if pluginCfg.TimeOut == time.Second*0 {
		pluginCfg.TimeOut = time.Second * 5
	}

	if pluginCfg.GroupWait == time.Second*0 {
		pluginCfg.GroupWait = time.Second * 1
	}
}

func pluginIsValid(path string) error {
	if testMode {
		return nil
	}
	var details fs.FileInfo
	var err error

	// check if it exists
	if details, err = os.Stat(path); err != nil {
		return errors.Wrap(err, fmt.Sprintf("plugin at %s does not exist", path))
	}

	// check if it is owned by current user
	currentUser, err := user.Current()
	if err != nil {
		return errors.Wrap(err, "while getting current user")
	}
	procAttr, err := getProcessAtr(currentUser.Username, currentUser.Username)
	if err != nil {
		return errors.Wrap(err, "while getting process attributes")
	}
	stat := details.Sys().(*syscall.Stat_t)
	if stat.Uid != procAttr.Credential.Uid || stat.Gid != procAttr.Credential.Gid {
		return fmt.Errorf("plugin at %s is not owned by %s user and group", path, currentUser.Username)
	}

	if (int(details.Mode()) & 2) != 0 {
		return fmt.Errorf("plugin at %s is world writable, world writable plugins are invalid", path)
	}
	return nil
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

func getProcessAtr(username string, groupname string) (*syscall.SysProcAttr, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}
	g, err := user.LookupGroup(groupname)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, err
	}
	if uid < 0 && uid > math.MaxInt32 {
		return nil, fmt.Errorf("out of bound uid")
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return nil, err
	}
	if gid < 0 && gid > math.MaxInt32 {
		return nil, fmt.Errorf("out of bound gid")
	}
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}, nil
}

func getUUID() (string, error) {
	d, err := os.ReadFile("/proc/sys/kernel/random/uuid")
	if err != nil {
		return "", err
	}
	return string(d), nil
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
	template, err := template.New("").Funcs(sprig.TxtFuncMap()).Parse(format)
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
