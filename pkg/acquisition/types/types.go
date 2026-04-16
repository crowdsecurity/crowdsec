package types

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// DataSource is the common interface implemented by all acquisition modules.
//
// A DataSource can always be configured from YAML.
type DataSource interface {
	// identity, lifecycle
	
	// GetMode returns the operating mode of the datasource (e.g. TAIL, CAT, SERVER).
	GetMode() string

	// GetName returns the module name (e.g. "file", "journalctl", "docker").
	GetName() string

	// GetUuid returns a unique identifier for this datasource instance.
	GetUuid() string

	Dump() any

	// CanRun reports whether the datasource can run on the current platform/environment
	// (e.g. journalctl not available on some systems like BSD).
	CanRun() error

	// configuration

	// UnmarshalConfig decodes and pre-validates the YAML datasource configuration.
	// Implementations should validate everything that can be checked without I/O.
	UnmarshalConfig(yamlConfig []byte) error

	// Configure completes datasource configuration and performs runtime checks.
	Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error
}

// DataSourceFactory constructs a new unconfigured DataSource instance.
type DataSourceFactory func() DataSource

// BatchFetcher represents a data source that produces a finite set of events.
//
// Implementations should:
//
//  - send events to the output channel until the input is fully consumed
//  - return (nil) early when the context is canceled
//  - return errors if acquisition fails
type BatchFetcher interface {
	// Start one shot acquisition(eg, cat a file)
	OneShot(ctx context.Context, out chan pipeline.Event) error
}

// Fetcher works like BatchFetcher but still relies on tombs, which are being replaced by context cancellation.
// New datasources are expected to implement BatchFetcher instead.
type Fetcher interface {
	OneShotAcquisition(ctx context.Context, out chan pipeline.Event, acquisTomb *tomb.Tomb) error
}

// RestartableStreamer represents a data source that produces an ongoing, potentially unbounded stream of events.
//
// Implementations should:
//
//  - send events to the output channel, continuously
//  - return (nil) when the context is canceled
//  - return errors if acquisition fails
//  - as much as possible, do not attempt retry/backoff even for transient connection
//    failures, but treat them as errors. The caller is responsible for supervising
//    Stream(), and restarting it as needed. There is currently no way to differentiate
//    retryable vs permanent errors.
type RestartableStreamer interface {
	// Start live acquisition (eg, tail a file)
	Stream(ctx context.Context, out chan pipeline.Event) error
}

// Tailer has the same pupose as RestartableStreamer (provide ongoing events) but
// is responsible for spawning its own goroutines, and handling errors and retries.
// New datasources are expected to implement RestartableStreamer instead.
type Tailer interface {
	StreamingAcquisition(ctx context.Context, out chan pipeline.Event, acquisTomb *tomb.Tomb) error
}

// MetricsProvider exposes Prometheus collectors owned by a datasource.
type MetricsProvider interface {
	// GetMetrics returns collectors for full (non-aggregated) metrics.
	GetMetrics() []prometheus.Collector

	// GetAggregMetrics returns collectors for aggregated metrics (reduced cardinality).
	GetAggregMetrics() []prometheus.Collector
}

// DSNConfigurer is implemented by datasources that support command-line / DSN-based configuration.
type DSNConfigurer interface {
	// ConfigureByDSN configures the datasource from a DSN string and labels.
	ConfigureByDSN(ctx context.Context, dsn string, labels map[string]string, logger *log.Entry, uniqueID string) error
}

// LAPIClientAware is implemented by datasources that need access to the Local API client configuration.
type LAPIClientAware interface {
	SetClientConfig(config *csconfig.LocalApiClientCfg)
}

// HubAware is implemented by datasources that need access to the Hub (e.g. for appsec rules/scenarios).
type HubAware interface {
	SetHub(hub *cwhub.Hub)
}
