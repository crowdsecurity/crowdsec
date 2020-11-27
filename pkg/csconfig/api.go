package csconfig

import log "github.com/sirupsen/logrus"

type APICfg struct {
	Client *LocalApiClientCfg `yaml:"client"`
	Server *LocalApiServerCfg `yaml:"server"`
}

type ApiCredentialsCfg struct {
	URL      string `yaml:"url,omitempty" json:"url,omitempty"`
	Login    string `yaml:"login,omitempty" json:"login,omitempty"`
	Password string `yaml:"password,omitempty" json:"-"`
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
	InsecureSkipVerify  *bool              `yaml:"insecure_skip_verify"` // check if api certificate is bad or not
}

/*local api service configuration*/
type LocalApiServerCfg struct {
	ListenURI    string              `yaml:"listen_uri,omitempty"` //127.0.0.1:8080
	TLS          *TLSCfg             `yaml:"tls"`
	DbConfig     *DatabaseCfg        `yaml:"-"`
	LogDir       string              `yaml:"-"`
	OnlineClient *OnlineApiClientCfg `yaml:"online_client"`
	ProfilesPath string              `yaml:"profiles_path,omitempty"`
	Profiles     []*ProfileCfg       `yaml:"-"`
	LogLevel     *log.Level          `yaml:"log_level"`
}

type TLSCfg struct {
	CertFilePath string `yaml:"cert_file"`
	KeyFilePath  string `yaml:"key_file"`
}
