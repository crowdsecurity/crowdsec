package csplugin

import (
	"os"
	"text/template"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var helpers = template.FuncMap{
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
	"CrowdsecCTI": exprhelpers.CrowdsecCTI,
	"Hostname":    os.Hostname,
}

func funcMap() template.FuncMap {
	return helpers
}
