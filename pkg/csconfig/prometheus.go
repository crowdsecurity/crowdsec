package csconfig

type PrometheusCfg struct {
	Enabled    bool   `yaml:"enabled"`
	Level      string `yaml:"level"` //aggregated|full
	ListenAddr string `yaml:"listen_addr"`
	ListenPort int    `yaml:"listen_port"`
}
