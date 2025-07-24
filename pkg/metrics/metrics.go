package metrics

import (
	"errors"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

type MetricsLevelConfig string

const (
	MetricsLevelNone       MetricsLevelConfig = "none"
	MetricsLevelAggregated MetricsLevelConfig = "aggregated"
	MetricsLevelFull       MetricsLevelConfig = "full"
	// MetricsLevelDefault is the default metrics level.
	MetricsLevelDefault MetricsLevelConfig = MetricsLevelFull
)

var ErrInvalidMetricsLevel = errors.New("invalid metrics level")

type AcquisitionMetricsLevel int

const (
	AcquisitionMetricsLevelNone       AcquisitionMetricsLevel       = iota // No metrics
	AcquisitionMetricsLevelAggregated                                      // Aggregated metrics
	AcquisitionMetricsLevelFull                                            // Full metrics
	AcquisitionMetricsLevelDefault    = AcquisitionMetricsLevelFull        // Default metrics level
)

func RegisterMetrics(metricsLevel MetricsLevelConfig) error {
	switch metricsLevel {
	case MetricsLevelNone:
		// Do not register any metrics
	case MetricsLevelAggregated:
		prometheus.MustRegister(GlobalParserHits, GlobalParserHitsOk, GlobalParserHitsKo,
			GlobalCsInfo, GlobalParsingHistogram, GlobalPourHistogram,
			BucketsUnderflow, BucketsCanceled, BucketsInstantiation, BucketsOverflow,
			LapiRouteHits,
			BucketsCurrentCount,
			CacheMetrics, RegexpCacheMetrics, NodesWlHitsOk, NodesWlHits)
	case MetricsLevelFull:
		prometheus.MustRegister(GlobalParserHits, GlobalParserHitsOk, GlobalParserHitsKo,
			NodesHits, NodesHitsOk, NodesHitsKo,
			GlobalCsInfo, GlobalParsingHistogram, GlobalPourHistogram,
			LapiRouteHits, LapiMachineHits, LapiBouncerHits, LapiNilDecisions, LapiNonNilDecisions, LapiResponseTime,
			BucketsPour, BucketsUnderflow, BucketsCanceled, BucketsInstantiation, BucketsOverflow, BucketsCurrentCount,
			GlobalActiveDecisions, GlobalAlerts, NodesWlHitsOk, NodesWlHits,
			CacheMetrics, RegexpCacheMetrics)
	default:
		return fmt.Errorf("%w: %s", ErrInvalidMetricsLevel, metricsLevel)
	}
	return nil
}
