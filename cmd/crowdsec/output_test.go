package main

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func TestDedupAlerts(t *testing.T) {
	var alerts = []types.RuntimeAlert{
		{
			Sources: map[string]models.Source {
				"192.0.2.17": {
					IP: "192.0.2.17",
				},
				"192.0.2.21": {
					IP: "192.0.2.21",
				},
			},
			Alert: &models.Alert {
				Source: &models.Source {
					IP: "192.0.2.17",
				},
			},
		},
	}

	alertsToPush, _ := dedupAlerts(alerts)
	if len(alertsToPush) != len(alerts[0].Sources) {
		t.Errorf("Deduplication failure: %d sources and %d alerts.", len(alerts[0].Sources), len(alertsToPush))
	}
	var found bool
	for _, src := range alerts[0].Sources {
		found = false
		for _, alert := range alertsToPush {
			if *alert.Source == src {
				found = true
			}
		}
		if !found {
			t.Errorf("Source with IP %s was not duplicated.", src.IP)
		}
	}
}
