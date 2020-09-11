package csconfig

type APIServerConfig struct {
	URL      string `yaml:"url"`
	CertPath string `yaml:"cert_path"`
	LogFile  string `yaml:"log_file"`
}
