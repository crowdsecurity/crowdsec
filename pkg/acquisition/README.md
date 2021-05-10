# pkg/acquisition

## What is it

`pkg/acquisition` is in charge of reading data sources and feeding events to the parser(s).
Most data sources can either be used :
 - in [one-shot](https://doc.crowdsec.net/v1.X/docs/user_guide/forensic_mode/#forensic-mode) mode : data source (ie. file) is read at once
 - in streaming mode : data source is constantly monitored, and events are fed to the parsers in real time

## Scope

This documentation aims at providing guidelines for implementation of new data sources.

# Writting modules

Each module must implement the `DataSource` interface.

```golang
type DataSource interface {
	GetMetrics() []prometheus.Collector              // Returns pointers to metrics that are managed by the module
	Configure([]byte, *log.Entry) error              // Configure the datasource
	ConfigureByDSN(string, string, *log.Entry) error // Configure the datasource
	GetMode() string                                 // Get the mode (TAIL, CAT or SERVER)
	GetName() string
	OneShotAcquisition(chan types.Event, *tomb.Tomb) error   // Start one shot acquisition(eg, cat a file)
	StreamingAcquisition(chan types.Event, *tomb.Tomb) error // Start live acquisition (eg, tail a file)
	CanRun() error                                           // Whether the datasource can run or not (eg, journalctl on BSD is a non-sense)
	Dump() interface{}
}
```

Ground rules :

 - All modules must respect the `tomb.Tomb`
 - `StreamingAcquisition` starts dedicated routines (via the `tomb.Tomb`) and returns, while `OneShotAcquisition` returns when datasource is consumed
 - `ConfigureByDSN` allows to configure datasource via cli for command-line invokation. Liberties can be taken with dsn format
 - Each datasource will be given a logger at configuration time, that is configured according to `DataSourceCommonCfg`. It is advised to customize it via [`.WithFields`](https://pkg.go.dev/github.com/sirupsen/logrus#WithFields) to take advantage of structured logging.

Note about configuration format :

 - Each data source can have their custom configuration.
 - All datasource share a "common" configuration section (`DataSourceCommonCfg`). To achieve this, you might want to inlines `DataSourceCommonCfg` in your datasource-specific configuration structure.


## Interface methods

### GetMetrics

Each data source can and should return custom prometheus metrics.
This is called for each data source that has at least one configured instance.

### Configure 

Configure is fed with the raw yaml configuration for your data source.
This is meant to allow freedom for each data source's configurations.

## ConfigureByDSN

When used in one-shot mode, your datasource is going to be configured via cli arguments.
The first argument is the `dsn`, the second on is the `label->type` to set on the logs.

Datasource implementations are allowed a lot of freedom around the [`dsn`](https://en.wikipedia.org/wiki/Data_source_name) specifications, but are expected :

 - to allow `log_level` configuration via dsn (ie. `mod://source;log_level=trace`)

## GetMode

Returns the mode `TAIL_MODE` or `CAT_MODE` of the current instance.

## OneShotAcquisition

Start a one-shot (or `CAT_MODE`, commonly used for forensic) acquisition that is expected to return once the datasource has been consumed.

## StreamingAcquisition

Start a streaming (or `TAIL_MODE`, commonly used when crowdsec runs as a daemon) acquisition. Starts appropriate go-routines via the `tomb.Tomb` and returns.

## CanRun

Can be used to prevent specific data source to run on specific platforms (ie. journalctl on BSD)

# BoilerPlate code

Taking a look at `acquisition_test.go` is advised for up-to-date boilerplate code.

```golang

type MockSource struct {
	configuration.DataSourceCommonCfg `yaml:",inline"`
	Toto                              string `yaml:"toto"`
	logger                            *log.Entry
}

func (f *MockSource) Configure(cfg []byte, logger *log.Entry) error {
	if err := yaml.UnmarshalStrict(cfg, &f); err != nil {
		return errors.Wrap(err, "while unmarshaling to reader specific config")
	}
	if f.Mode == "" {
		f.Mode = configuration.CAT_MODE
	}
	if f.Mode != configuration.CAT_MODE && f.Mode != configuration.TAIL_MODE {
		return fmt.Errorf("mode %s is not supported", f.Mode)
	}
	if f.Toto == "" {
		return fmt.Errorf("expect non-empty toto")
	}
    f.logger = logger.WithField("toto", f.Toto)
	return nil
}
func (f *MockSource) GetMode() string                                         { return f.Mode }
func (f *MockSource) OneShotAcquisition(chan types.Event, *tomb.Tomb) error   { return nil }
func (f *MockSource) StreamingAcquisition(chan types.Event, *tomb.Tomb) error { return nil }
func (f *MockSource) CanRun() error                                           { return nil }
func (f *MockSource) GetMetrics() []prometheus.Collector                      { return nil }
func (f *MockSource) Dump() interface{}                                       { return f }
func (f *MockSource) GetName() string                                         { return "mock" }
func (f *MockSource) ConfigureByDSN(string, string, *log.Entry) error {
	return fmt.Errorf("not supported")
}

```

