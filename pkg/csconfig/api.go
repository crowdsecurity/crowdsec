package csconfig

type APICfg struct {
	Client *LocalApiClientCfg `yaml:"client"`
	Server *LocalApiServerCfg `yaml:"server"`
}

type ApiCredentialsCfg struct {
	URL      string `yaml:"url,omitempty"`
	Login    string `yaml:"login,omitempty"`
	Password string `yaml:"password,omitempty"`
}

/*global api config (for lapi->oapi)*/
type OnlineApiClientCfg struct {
	CredentialsFilePath string             `yaml:"credentials_path,omitempty"` //credz will be edited by software, store in diff file
	Credentials         *ApiCredentialsCfg `yaml:"-"`
}

/*local api config (for crowdsec/cscli->lapi)*/
type LocalApiClientCfg struct {
	CredentialsFilePath string             `yaml:"credentials_path,omitempty"` //credz will be edited by software, store in diff file
	Credentials         *ApiCredentialsCfg `yaml:"-"`
}

/*local api service configuration*/
type LocalApiServerCfg struct {
	CertFilePath string              `yaml:"cert_path,omitempty"`
	ListenURI    string              `yaml:"listen_uri,omitempty"` //127.0.0.1:4242
	DbConfig     *DatabaseCfg        `yaml:"-"`
	LogDir       string              `yaml:"-"`
	OnlineClient *OnlineApiClientCfg `yaml:"online_client"`
}
