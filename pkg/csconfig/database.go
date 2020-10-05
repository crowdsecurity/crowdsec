package csconfig

type DatabaseCfg struct {
	User     string      `yaml:"user"`
	Password string      `yaml:"password"`
	DbName   string      `yaml:"db_name"`
	Host     string      `yaml:"host"`
	Port     int         `yaml:"port"`
	DbPath   string      `yaml:"db_path"`
	Type     string      `yaml:"type"`
	Flush    *FlushDBCfg `yaml:"flush"`
}

type FlushDBCfg struct {
	MaxItems *int    `yaml:"max_items"`
	MaxAge   *string `yaml:"max_age"`
}
