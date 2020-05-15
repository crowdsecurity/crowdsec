package cwplugin

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"plugin"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// the structure returned by the function New() of the plugin must match this interface
type Backend interface {
	Insert(types.SignalOccurence) error
	ReadAT(time.Time) ([]map[string]string, error)
	Delete(string) (int, error)
	Init(map[string]string) error
	Flush() error
	DeleteAll() error
}

type BackendPlugin struct {
	Name           string `yaml:"name"`
	Path           string `yaml:"path"`
	ConfigFilePath string
	Config         map[string]string `yaml:"config"`
	ID             string
	funcs          Backend
}

type BackendManager struct {
	backendPlugins map[string]BackendPlugin
}

func NewBackendPlugin(path string, isDaemon bool) (*BackendManager, error) {
	var files []string
	var backendManager = &BackendManager{}
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if filepath.Ext(path) == ".yaml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		panic(err)
	}

	backendManager.backendPlugins = make(map[string]BackendPlugin, len(files))

	for _, file := range files {
		var newPlugin BackendPlugin
		log.Debugf("opening plugin '%s'", file)
		bConfig, err := ioutil.ReadFile(file)
		if err != nil {
			log.Errorf("unable to open file '%s' : %s, skipping", file, err)
			continue
		}
		if err := yaml.UnmarshalStrict(bConfig, &newPlugin); err != nil {
			log.Errorf("parsing '%s' yaml error : %s, skipping", file, err)
			continue
		}
		plug, err := plugin.Open(newPlugin.Path)
		if err != nil {
			return nil, err
		}
		//Lookup a function called 'New' to get the plugin interface
		symbol, err := plug.Lookup("New")
		if err != nil {
			return nil, fmt.Errorf("no 'New' function in plugin : %s", err)
		}
		symNew, ok := symbol.(func() interface{})
		if !ok {
			log.Errorf("plugin '%s' do not implement a GetFunctions() that return a list of string, skipping", file)
			continue
		}

		// cast the return interface to Backend interface
		plugNew := symNew()
		bInterface, ok := plugNew.(Backend)
		if !ok {
			return nil, fmt.Errorf("unexpected '%s' type, skipping", newPlugin.Name)
		}

		// Add the interface and Init()
		newPlugin.funcs = bInterface
		if isDaemon {
			newPlugin.Config["flush"] = "true"
		} else {
			newPlugin.Config["flush"] = "false"
		}

		err = newPlugin.funcs.Init(newPlugin.Config)
		if err != nil {
			return nil, fmt.Errorf("plugin '%s' init error : %s", newPlugin.Name, err)
		}
		log.Infof("backend plugin '%s' loaded", newPlugin.Name)
		backendManager.backendPlugins[newPlugin.Name] = newPlugin

	}
	log.Debugf("loaded %d backend plugins", len(backendManager.backendPlugins))
	if len(backendManager.backendPlugins) == 0 {
		return nil, fmt.Errorf("no plugins loaded from %s", path)
	}
	return backendManager, nil
}

func (b *BackendManager) Delete(target string) (int, error) {
	var err error
	var nbDel int
	for _, plugin := range b.backendPlugins {
		nbDel, err = plugin.funcs.Delete(target)
		if err != nil {
			return 0, fmt.Errorf("failed to delete : %s", err)
		}
	}
	return nbDel, nil
}

func (b *BackendManager) DeleteAll() error {
	var err error
	for _, plugin := range b.backendPlugins {
		err = plugin.funcs.DeleteAll()
		if err != nil {
			return fmt.Errorf("failed to delete : %s", err)
		}
	}
	return nil
}

// Insert the signal for the plugin specified in the config["plugin"] parameter
func (b *BackendManager) InsertOnePlugin(sig types.SignalOccurence, pluginName string) error {
	if val, ok := b.backendPlugins[pluginName]; ok {
		val.funcs.Insert(sig)
	} else {
		return fmt.Errorf("plugin '%s' not loaded", pluginName)
	}
	return nil
}

// Insert the signal for all the plugins
func (b *BackendManager) Insert(sig types.SignalOccurence) error {
	var err error
	for _, plugin := range b.backendPlugins {
		err = plugin.funcs.Insert(sig)
		if err != nil {
			return fmt.Errorf("flushing backend plugin '%s' failed: %s", plugin.Name, err)
		}
	}

	return nil
}

func (b *BackendManager) IsBackendPlugin(plugin string) bool {
	if _, ok := b.backendPlugins[plugin]; ok {
		return true
	}
	return false
}

func (b *BackendManager) ReadAT(timeAT time.Time) ([]map[string]string, error) {
	var ret []map[string]string
	var err error
	for _, plugin := range b.backendPlugins {
		ret, err = plugin.funcs.ReadAT(timeAT)
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func (b *BackendManager) Flush() error {
	var err error
	for _, plugin := range b.backendPlugins {
		err = plugin.funcs.Flush()
		if err != nil {
			return fmt.Errorf("flushing backend plugin '%s' failed: %s", plugin.Name, err)
		}
	}
	return nil
}
