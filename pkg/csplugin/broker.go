package csplugin

import (
	"context"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/template"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	plugin "github.com/hashicorp/go-plugin"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v2"
)

type PluginBroker struct {
	ProfileConfigs              []*csconfig.ProfileCfg
	PluginChannel               chan ProfileAlert
	NotificationConfigsByPlugin map[string][][]byte // "slack" -> []{config1, config2}
	PluginConfigByName          map[string]PluginConfig
	PluginPaths                 []string
	PluginMap                   map[string]plugin.Plugin
	NotificationPluginByName    map[string]Notifier
}

type ProfileAlert struct {
	ProfileID uint
	Alert     *models.Alert
}

// temporary holder to determine where to dispatch config
type PluginConfig struct {
	Type   string `yaml:"type"`
	Name   string `yaml:"name"`
	Format string `yaml:"format"`
}

func (pb *PluginBroker) Init(profileConfigs []*csconfig.ProfileCfg, configPaths *csconfig.ConfigurationPaths) error {
	pb.PluginChannel = make(chan ProfileAlert)
	pb.NotificationConfigsByPlugin = make(map[string][][]byte)
	pb.NotificationPluginByName = make(map[string]Notifier)
	pb.PluginMap = make(map[string]plugin.Plugin)
	pb.PluginConfigByName = make(map[string]PluginConfig)

	pb.ProfileConfigs = profileConfigs

	if err := pb.LoadConfig(configPaths.NotificationDir); err != nil {
		return err
	}

	err := pb.LoadPlugins(configPaths.PluginDir)
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
		pb.NotificationConfigsByPlugin[pc.Type] = append(pb.NotificationConfigsByPlugin[pc.Type], data)
	}
	return nil
}

func (pb *PluginBroker) LoadPlugins(path string) error {
	// TODO: break this into smaller methods
	binaryPaths, err := listFilesAtPath(path)
	if err != nil {
		return err
	}
	for _, binaryPath := range binaryPaths {
		// if !pluginIsValid(binaryPath){
		// 	continue
		// }
		name, Type, err := getPluginNameAndTypeFromPath(binaryPath)
		if err != nil {
			log.Error(err)
			continue
		}
		// TODO: assign this by using some sort of map.
		if Type == "notification" {
			log.Info("found notification plugin")
			pb.PluginMap[name] = &NotifierPlugin{}
			// TODO: do the permission drop here.
			cmd := exec.Command("sh", "-c", binaryPath)
			cmd.SysProcAttr = getProccessAtr()
			uuid, err := getUUID()
			if err != nil {
				return err
			}

			var Handshake = plugin.HandshakeConfig{
				// This isn't required when using VersionedPlugins
				ProtocolVersion:  1,
				MagicCookieKey:   "CROWDSEC_PLUGIN_KEY",
				MagicCookieValue: uuid,
			}
			c := plugin.NewClient(&plugin.ClientConfig{
				HandshakeConfig:  Handshake,
				Plugins:          pb.PluginMap,
				Cmd:              cmd,
				AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
			})
			client, err := c.Client()
			if err != nil {
				return err
			}
			raw, err := client.Dispense(name)
			if err != nil {
				return err
			}
			pluginClient := raw.(Notifier)
			for _, config := range pb.NotificationConfigsByPlugin[name] {
				pc := PluginConfig{}
				// TODO: Refactor to avoid double marshalling and drop config once sent to plugin
				err = yaml.Unmarshal(config, &pc)
				if err != nil {
					return err
				}
				pb.PluginConfigByName[pc.Name] = pc
				pb.NotificationPluginByName[pc.Name] = pluginClient
				pluginClient.Configure(context.Background(), &Config{Config: config})
			}
		}
	}
	return nil
}

func (pb *PluginBroker) Run() error {
	for {
		profileAlert := <-pb.PluginChannel
		for _, pluginName := range pb.ProfileConfigs[profileAlert.ProfileID].Notifications {
			template, err := template.New("").Parse(
				pb.PluginConfigByName[pluginName].Format,
			)
			if err != nil {
				return err
			}
			b := new(strings.Builder)
			err = template.Execute(b, profileAlert.Alert)
			if err != nil {
				return err
			}
			log.Debugf("sending alert to %s", pluginName)
			go func() {
				pb.NotificationPluginByName[pluginName].Notify(
					context.Background(), &Notification{
						Text: b.String(),
						Name: pluginName,
					},
				)
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

	// check if it is world-writable
	if unix.Access(path, unix.W_OK) != nil {
		return false
	}

	// check if it is owned by root
	stat := details.Sys().(*syscall.Stat_t)
	if stat.Uid != 0 || stat.Gid != 0 {
		return false
	}
	return true
}

// helper which lists all files in the given directory non-recursively
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
	if d, err := ioutil.ReadFile("/proc/sys/kernel/random/uuid"); err != nil {
		return "", err
	} else {
		return string(d), nil
	}
}
