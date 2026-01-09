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

// The interface each datasource must implement
type DataSource interface {
	// identity, lifecycle
	GetMode() string                                                                                    // Get the mode (TAIL, CAT or SERVER)
	GetName() string                                                                                    // Get the name of the module
	GetUuid() string                                                                                    // Get the unique identifier of the datasource
	Dump() any
	CanRun() error                                                                                      // Whether the datasource can run or not (eg, journalctl on BSD is a non-sense)

	// configuration
	UnmarshalConfig(yamlConfig []byte) error                                                            // Decode and pre-validate the YAML datasource - anything that can be checked before runtime
	Configure(ctx context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error // Complete the YAML datasource configuration and perform runtime checks.
}

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

type MetricsProvider interface {
	// Returns pointers to metrics that are managed by the module
	GetMetrics() []prometheus.Collector

	// Returns pointers to metrics that are managed by the module (aggregated mode, limits cardinality)
	GetAggregMetrics() []prometheus.Collector
}

type DSNConfigurer interface {
	// Configure the datasource
	ConfigureByDSN(ctx context.Context, dsn string, labels map[string]string, logger *log.Entry, uniqueID string) error
}

type LAPIClientAware interface {
	SetClientConfig(config *csconfig.LocalApiClientCfg)
}

type HubAware interface {
	SetHub(hub *cwhub.Hub)
}
