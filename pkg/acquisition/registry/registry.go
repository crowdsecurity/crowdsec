package registry

import (
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/types"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion/component"
)

// AcquisitionSources is filled at init time so the application can report
// if the datasources are unsupported, or excluded from the build.
var AcquisitionSources = map[string]func() types.DataSource{}

// RegisterDataSource registers a datasource in the AcquisitionSources map.
// It must be called in the init() function of the datasource package, and the datasource name
// must be declared with a nil value in the map, to allow for conditional compilation.
func RegisterDataSource(dataSourceType string, dsGetter func() types.DataSource) {
	component.Register("datasource_" + dataSourceType)

	AcquisitionSources[dataSourceType] = dsGetter
}
