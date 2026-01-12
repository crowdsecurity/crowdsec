package registry

import (
	"errors"
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion/component"
)

// factoriesByName is filled at init time so the application can report
// if the datasources are unsupported, or simply excluded from the build.
// We don't need to guard with a mutex if all writes to the map are done
// inside init() functions, as they are guaranteed to run sequentially.
var factoriesByName = map[string]func() types.DataSource{}

// RegisterFactory registers a datasource constructor in the factoriesByName map.
// It must be called in the init() function of the datasource package.
// In addition, the build component is registered so it will be reported
// by the "cscli version / crowdsec --version" commands.
func RegisterFactory(moduleName string, factory types.DataSourceFactory) {
	component.Register("datasource_" + moduleName)
	factoriesByName[moduleName] = factory
}

func LookupFactory(moduleName string) (types.DataSourceFactory, error) {
	source, registered := factoriesByName[moduleName]
	if registered {
		return source, nil
	}

	built, known := component.Built["datasource_"+moduleName]

	if moduleName == "" {
		return nil, errors.New("data source type is empty")
	}

	if !known {
		return nil, fmt.Errorf("unknown data source %s", moduleName)
	}

	if built {
		panic("datasource " + moduleName + " is built but not registered")
	}

	return nil, fmt.Errorf("data source %s is not built in this version of crowdsec", moduleName)
}
