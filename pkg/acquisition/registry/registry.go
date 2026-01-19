package registry

import (
	"errors"
	"fmt"
	"sync"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion/component"
)

// factoriesByName is filled at init time so the application can report
// if the datasources are unsupported, or simply excluded from the build.
var (
	factoriesByName = map[string]types.DataSourceFactory{}
	mu sync.RWMutex
)

func register(module string, factory types.DataSourceFactory) (restore func()) {
	if module == "" {
		panic("registry: datasource type is empty")
	}

	if factory == nil {
		panic("registry: factory is nil for " + module)
	}

	mu.Lock()
	prev, had := factoriesByName[module]
	factoriesByName[module] = factory
	mu.Unlock()

	return func() {
	        mu.Lock()
	        if had {
			factoriesByName[module] = prev
		} else {
			delete(factoriesByName, module)
		}
		mu.Unlock()
	}
}

// RegisterFactory registers a datasource constructor in the factoriesByName map.
// It must be called in the init() function of the datasource package.
// In addition, the build component is registered so it will be reported
// by the "cscli version / crowdsec --version" commands.
func RegisterFactory(module string, factory types.DataSourceFactory) {
	component.Register("datasource_" + module)
	register(module, factory)
}

// RegisterTestFactory does not attempt to register it as a component,
// production code should call RegisterFactory() instead and make the datasource
// code optional using the appropriate build tag.
// This function may be called outside init().
func RegisterTestFactory(module string, factory types.DataSourceFactory) (restore func()) {
	return register(module, factory)
}

func LookupFactory(module string) (types.DataSourceFactory, error) {
	if module == "" {
		return nil, errors.New("data source type is empty")
	}

	mu.RLock()
	factory, registered := factoriesByName[module]
	mu.RUnlock()

	if registered {
		return factory, nil
	}

	built, known := component.Built["datasource_"+module]
	if !known {
		return nil, fmt.Errorf("unknown data source %s", module)
	}

	if built {
		panic("datasource " + module + " is built but not registered")
	}

	return nil, fmt.Errorf("data source %s is not built in this version of crowdsec", module)
}
