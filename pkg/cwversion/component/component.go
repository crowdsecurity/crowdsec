package component

// a map of all the known components, and whether they are built-in or not.
// This is populated as soon as possible by the respective init() functions

var Built = map[string]bool {
	"datasource_appsec":     false,
	"datasource_cloudwatch": false,
	"datasource_docker":     false,
	"datasource_file":       false,
	"datasource_journalctl": false,
	"datasource_k8s-audit":  false,
	"datasource_kafka":      false,
	"datasource_kinesis":    false,
	"datasource_loki":       false,
	"datasource_s3":         false,
	"datasource_syslog":     false,
	"datasource_wineventlog":false,
	"cscli_setup":           false,
}

func Register(name string) {
	if _, ok := Built[name]; !ok {
		// having a list of the disabled components is essential
		// to debug users' issues
		panic("cannot register unknown compile-time component: "+name)
	}

	Built[name] = true
}
