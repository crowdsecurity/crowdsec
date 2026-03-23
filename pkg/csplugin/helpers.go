package csplugin

import (
	"html"
	"os"
	"text/template"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/cticlient/ctiexpr"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var funcMap = template.FuncMap{
	"GetMeta": func(a *models.Alert, metaName string) []string {
		var metaValues []string
		for _, evt := range a.Events {
			for _, meta := range evt.Meta {
				if meta.Key == metaName {
					metaValues = append(metaValues, meta.Value)
				}
			}
		}
		return metaValues
	},
	"CrowdsecCTI": func(x string) any {
		ret, err := ctiexpr.CrowdsecCTI(x)
		if err != nil {
			log.Warningf("error while calling CrowdsecCTI : %s", err)
		}
		return ret
	},
	"Hostname":   os.Hostname,
	"HTMLEscape": html.EscapeString,
}
