package csconfig

// PProfCfg configures the dedicated listener for the Go pprof profiling
// endpoints (/debug/pprof/*). pprof is enabled by default but bound to
// 127.0.0.1, so that transient CPU/memory issues can be profiled (and
// collected by "cscli support dump") without a configuration change or a
// restart, while never being exposed to the network unless the operator
// explicitly sets listen_addr.
type PProfCfg struct {
	Enabled    *bool  `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	ListenPort int    `yaml:"listen_port"`
}
