package csconfig

/*cscli specific config, such as hub directory*/
type Hub struct {
	HubDir       string `yaml:"-"`
	ConfigDir    string `yaml:"-"`
	HubIndexFile string `yaml:"-"`
	DataDir      string `yaml:"-"`
}
