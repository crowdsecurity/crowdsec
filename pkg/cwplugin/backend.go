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
	Shutdown() error
	DeleteAll() error
}

type BackendPlugin struct {
	Name           string `yaml:"name"`
	Path           string `yaml:"path"`
	ConfigFilePath string
	//Config is passed to the backend plugin.
	//It contains specific plugin config + plugin config from main yaml file
	Config map[string]string `yaml:"config"`
	ID     string
	funcs  Backend
}

type BackendManager struct {
	backendPlugins map[string]BackendPlugin
}

func NewBackendPlugin(outputConfig map[string]string) (*BackendManager, error) {
	var files []string
	var backendManager = &BackendManager{}
	var path string

	if v, ok := outputConfig["backend"]; ok {
		path = v
	} else {
		return nil, fmt.Errorf("missing 'backend' (path to backend plugins)")
	}
	//var path = output.BackendFolder
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
			return nil, fmt.Errorf("unexpected '%s' type (%T), skipping", newPlugin.Name, plugNew)
		}

		// Add the interface and Init()
		newPlugin.funcs = bInterface
		// Merge backend config from main config file
		// Merge backend config from main config file
		if v, ok := outputConfig["debug"]; ok {
			newPlugin.Config["debug"] = v
		} else {
			newPlugin.Config["debug"] = "false"
		}

		if v, ok := outputConfig["max_records"]; ok {
			newPlugin.Config["max_records"] = v
		} else {
			log.Warningf("missing 'max_records' parameters, setting to default (1000)")
			newPlugin.Config["max_records"] = "1000"
		}

		if v, ok := outputConfig["max_records_age"]; ok {
			newPlugin.Config["max_records_age"] = v
		} else {
			log.Warningf("missing 'max_records_age' parameters, setting to default (30d)")
			newPlugin.Config["max_records_age"] = "30d"
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

func (b *BackendManager) Shutdown() error {
	var err error
	for _, plugin := range b.backendPlugins {
		err = plugin.funcs.Shutdown()
		if err != nil {
			return fmt.Errorf("failed to shutdown : %s", err)
		}
	}
	return nil
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
		if err := val.funcs.Insert(sig); err != nil {
			return fmt.Errorf("failed to load %s : %s", pluginName, err)
		}
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
