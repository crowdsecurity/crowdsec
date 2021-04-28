package configuration

type DataSourceCommonCfg struct {
	Mode      string            `yaml:"mode,omitempty"`
	Labels    map[string]string `yaml:"labels,omitempty"`
	Profiling bool              `yaml:"profiling,omitempty"`
	Type      string            `yaml:"type,omitempty"`
}

type FileSourceCfg struct {
	DataSourceCommonCfg
	filename string
}

var TAIL_MODE = "tail"
var CAT_MODE = "cat"
var SERVER_MODE = "server" // No difference with tail, just a bit more verbose
