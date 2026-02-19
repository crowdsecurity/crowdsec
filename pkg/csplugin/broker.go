package csplugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/google/uuid"
	plugin "github.com/hashicorp/go-plugin"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/csstring"
	"github.com/crowdsecurity/go-cs-lib/slicetools"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/logging"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
)

var pluginMutex sync.Mutex

const (
	PluginProtocolVersion uint   = 1
	CrowdsecPluginKey     string = "CROWDSEC_PLUGIN_KEY"
)

// PluginBroker is responsible for running the plugins and dispatching events
// It receives all the events from the main process and stacks them up
// It is as well notified by the watcher when it needs to deliver events to plugins (based on time or count threshold)
type PluginBroker struct {
	PluginChannel                   chan models.ProfileAlert
	alertsByPluginName              map[string][]*models.Alert
	profileConfigs                  []*csconfig.ProfileCfg
	pluginConfigByName              map[string]PluginConfig
	pluginMap                       map[string]plugin.Plugin
	notificationPluginByName        map[string]protobufs.NotifierServer
	watcher                         PluginWatcher
	pluginKillMethods               []func()
	pluginProcConfig                *csconfig.PluginCfg
	pluginsTypesToDispatch          map[string]struct{}
	newBackoff                      backoffFactory
}

// holder to determine where to dispatch config and how to format messages
type PluginConfig struct {
	Type           string        `yaml:"type"`
	Name           string        `yaml:"name"`
	GroupWait      time.Duration `yaml:"group_wait,omitempty"`
	GroupThreshold int           `yaml:"group_threshold,omitempty"`
	MaxRetry       uint          `yaml:"max_retry,omitempty"`
	TimeOut        time.Duration `yaml:"timeout,omitempty"`

	Format string `yaml:"format,omitempty"` // specific to notification plugins

	Config map[string]any `yaml:",inline"` // to keep the plugin-specific config
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (pc *PluginConfig) UnmarshalYAML(unmarshal func(any) error) error {
	type raw PluginConfig
	aux := raw{}

	if err := unmarshal(&aux); err != nil {
		return err
	}

	if aux.Type == "" {
		return errors.New("missing required field 'type'")
	}

	if aux.TimeOut == 0 {
		aux.TimeOut = time.Second * 5
	}

	*pc = PluginConfig(aux)
	return nil
}

type PluginConfigList []PluginConfig

func (pb *PluginBroker) Init(ctx context.Context, pluginCfg *csconfig.PluginCfg, profileConfigs []*csconfig.ProfileCfg, configPaths *csconfig.ConfigurationPaths) error {
	pb.PluginChannel = make(chan models.ProfileAlert)
	pb.notificationPluginByName = make(map[string]protobufs.NotifierServer)
	pb.pluginMap = make(map[string]plugin.Plugin)
	pb.pluginConfigByName = make(map[string]PluginConfig)
	pb.alertsByPluginName = make(map[string][]*models.Alert)
	pb.profileConfigs = profileConfigs
	pb.pluginProcConfig = pluginCfg
	pb.pluginsTypesToDispatch = make(map[string]struct{})

	if err := pb.loadConfig(configPaths.NotificationDir); err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if err := pb.loadPlugins(ctx, configPaths.PluginDir); err != nil {
		return fmt.Errorf("loading plugin: %w", err)
	}

	pb.watcher = PluginWatcher{}
	pb.watcher.Init(pb.pluginConfigByName, pb.alertsByPluginName)

	return nil
}

func (pb *PluginBroker) ensureBackoff() backoffFactory {
	if pb.newBackoff == nil {
		pb.newBackoff = defaultBackoffFactory
	}
	return pb.newBackoff
}

func (pb *PluginBroker) Kill() {
	for _, kill := range pb.pluginKillMethods {
		kill()
	}
}

func (pb *PluginBroker) Run(pluginTomb *tomb.Tomb) {
	// we get signaled via the channel when notifications need to be delivered to plugin (via the watcher)
	ctx := context.TODO()

	pb.watcher.Start(&tomb.Tomb{})

	for {
		select {
		case profileAlert := <-pb.PluginChannel:
			pb.addProfileAlert(profileAlert)

		case pluginName := <-pb.watcher.PluginEvents:
			// this can be run in goroutine, but then locks will be needed
			pluginMutex.Lock()
			log.Tracef("going to deliver %d alerts to plugin %s", len(pb.alertsByPluginName[pluginName]), pluginName)
			tmpAlerts := pb.alertsByPluginName[pluginName]
			pb.alertsByPluginName[pluginName] = make([]*models.Alert, 0)
			pluginMutex.Unlock()

			go func() {
				// Chunk alerts to respect group_threshold
				threshold := pb.pluginConfigByName[pluginName].GroupThreshold
				if threshold == 0 {
					threshold = 1
				}

				for _, chunk := range slicetools.Chunks(tmpAlerts, threshold) {
					if err := pb.pushNotificationsToPlugin(ctx, pluginName, chunk); err != nil {
						log.WithField("plugin:", pluginName).Error(err)
					}
				}
			}()

		case <-pluginTomb.Dying():
			log.Infof("pluginTomb dying")
			pb.watcher.tomb.Kill(errors.New("Terminating"))

			for {
				select {
				case <-pb.watcher.tomb.Dead():
					log.Info("killing all plugins")
					pb.Kill()

					return
				case pluginName := <-pb.watcher.PluginEvents:
					// this can be run in goroutine, but then locks will be needed
					pluginMutex.Lock()
					log.Tracef("going to deliver %d alerts to plugin %s", len(pb.alertsByPluginName[pluginName]), pluginName)
					tmpAlerts := pb.alertsByPluginName[pluginName]
					pb.alertsByPluginName[pluginName] = make([]*models.Alert, 0)
					pluginMutex.Unlock()

					if err := pb.pushNotificationsToPlugin(ctx, pluginName, tmpAlerts); err != nil {
						log.WithField("plugin:", pluginName).Error(err)
					}
				}
			}
		}
	}
}

func (pb *PluginBroker) addProfileAlert(profileAlert models.ProfileAlert) {
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
		if slices.Contains(profileCfg.Notifications, pluginName) {
			return true
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

		fin, err := os.Open(configFilePath)
		if err != nil {
			return fmt.Errorf("while opening %s: %w", configFilePath, err)
		}

		pluginConfigs, err := NewPluginConfigList(fin)
		if err != nil {
			return fmt.Errorf("error in %s: %w", configFilePath, err)
		}

		for _, pluginConfig := range pluginConfigs {
			if _, ok := pb.pluginConfigByName[pluginConfig.Name]; ok {
				log.Warningf("notification '%s' is defined multiple times", pluginConfig.Name)
			}

			pb.pluginConfigByName[pluginConfig.Name] = pluginConfig
			if !pb.profilesContainPlugin(pluginConfig.Name) {
				continue
			}
		}
	}

	return pb.verifyPluginConfigsWithProfile()
}

// checks whether every notification in profile has its own config file
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

// check whether each plugin in profile has its own binary
func (pb *PluginBroker) verifyPluginBinaryWithProfile() error {
	for _, profileCfg := range pb.profileConfigs {
		for _, pluginName := range profileCfg.Notifications {
			if _, ok := pb.notificationPluginByName[pluginName]; !ok {
				return fmt.Errorf("binary for plugin %s not found", pluginName)
			}
		}
	}

	return nil
}

func (pb *PluginBroker) loadPlugins(ctx context.Context, path string) error {
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

		pluginClient, err := pb.loadNotificationPlugin(ctx, pSubtype, binaryPath)
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

			data = []byte(csstring.StrictExpand(string(data), os.LookupEnv))

			_, err = pluginClient.Configure(ctx, &protobufs.Config{Config: data})
			if err != nil {
				return fmt.Errorf("while configuring %s: %w", pc.Name, err)
			}

			log.Infof("registered plugin %s", pc.Name)

			pb.notificationPluginByName[pc.Name] = pluginClient
		}
	}

	return pb.verifyPluginBinaryWithProfile()
}

func (pb *PluginBroker) loadNotificationPlugin(ctx context.Context, name string, binaryPath string) (protobufs.NotifierServer, error) {
	handshake, err := getHandshake()
	if err != nil {
		return nil, err
	}

	log.Debugf("Executing plugin %s", binaryPath)

	cmd, err := pb.CreateCmd(ctx, binaryPath)
	if err != nil {
		return nil, err
	}

	pb.pluginMap[name] = &NotifierPlugin{}
	l := logging.SubLogger(log.StandardLogger(), "plugin", log.TraceLevel)
	// We set the highest level to permit plugins to set their own log level
	// without that, crowdsec log level is controlling plugins level
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

	return raw.(protobufs.NotifierServer), nil
}

func (pb *PluginBroker) tryNotify(ctx context.Context, pluginName, message string) error {
	// config guard
	pc, ok := pb.pluginConfigByName[pluginName]
	if !ok {
		return fmt.Errorf("plugin %q: config not found", pluginName)
	}

	timeout := pc.TimeOut
	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)

	defer cancel()

	// plugin guard
	plugin, ok := pb.notificationPluginByName[pluginName]
	if !ok || plugin == nil {
		return fmt.Errorf("plugin %q: notifier not registered", pluginName)
	}

	_, err := plugin.Notify(
		ctxTimeout,
		&protobufs.Notification{
			Text: message,
			Name: pluginName,
		},
	)

	return err
}

func (pb *PluginBroker) pushNotificationsToPlugin(ctx context.Context, pluginName string, alerts []*models.Alert) error {
	logger := log.WithField("plugin", pluginName)

	logger.Debugf("pushing %d alerts to plugin", len(alerts))

	if len(alerts) == 0 {
		return nil
	}

	pluginCfg := pb.pluginConfigByName[pluginName]

	message, err := FormatAlerts(pluginCfg.Format, alerts)
	if err != nil {
		return fmt.Errorf("format alerts for notification: %w", err)
	}

	// make sure we have a default or custom backoff
	pb.ensureBackoff()

	err = retryWithBackoff(ctx, pluginCfg, logger, func(ctx context.Context) error {
		return pb.tryNotify(ctx, pluginName, message)
	}, pb.newBackoff)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			logger.Warn("delivery canceled during shutdown")
		} else {
			logger.Errorf("delivery failed after retries: %v", err)
		}
	}

	return err
}

func NewPluginConfigList(fin io.Reader) (PluginConfigList, error) {
	parsedConfigs := make(PluginConfigList, 0)

	dec := yaml.NewDecoder(fin)
	dec.SetStrict(true)

	idx := -1

	for {
		var pc PluginConfig

		idx += 1

		err := dec.Decode(&pc)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, fmt.Errorf("document %d: %w", idx, err)
		}

		// if the yaml document is empty, skip
		if reflect.DeepEqual(pc, PluginConfig{}) {
			continue
		}

		parsedConfigs = append(parsedConfigs, pc)
	}

	return parsedConfigs, nil
}

func getUUID() (string, error) {
	uuidv4, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	return uuidv4.String(), nil
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

func FormatAlerts(format string, alerts []*models.Alert) (string, error) {
	template, err := template.New("").Funcs(sprig.TxtFuncMap()).Funcs(funcMap).Parse(format)
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
