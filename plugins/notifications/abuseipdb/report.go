package main

import (
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type Report struct {
	Ip         string
	Categories string
	Comment    string
}

func (r Report) New(alert *models.Alert) *Report {
	r.Ip = alert.Source.IP
	r.Categories = Scenarios[*alert.Scenario]
	r.Comment = "[Crowdsec]: detected via: " + *alert.Scenario
	return &r
}

type ReportResponse struct {
	Data struct {
		IpAdress             string `json:"ipAddress"`
		AbuseConfidenceScore string `json:"abuseConfidenceScore"`
	}
}
