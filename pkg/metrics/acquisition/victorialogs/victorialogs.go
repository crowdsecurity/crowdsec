//go:build !no_datasource_victorialogs

package victorialogs_metrics

import (
	"github.com/crowdsecurity/crowdsec/pkg/metrics/acquisition"
	"github.com/prometheus/client_golang/prometheus"
)

const VictorialogsDataSourceLinesReadMetricName = "cs_victorialogssource_hits_total"

var VictorialogsDataSourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: VictorialogsDataSourceLinesReadMetricName,
		Help: "Total lines that were read.",
	},
	[]string{"source", "datasource_type", "label_type"})

//nolint:gochecknoinits
func init() {
	acquisition.RegisterAcquisitionMetric(VictorialogsDataSourceLinesReadMetricName)
}
