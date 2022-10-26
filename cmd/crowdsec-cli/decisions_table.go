package main

import (
	"fmt"
	"io"
	"strconv"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func decisionsTable(out io.Writer, alerts *models.GetAlertsResponse, printMachine bool) {
	t := newTable(out)
	t.SetRowLines(false)
	header := []string{"ID", "Source", "Scope:Value", "Reason", "Action", "Country", "AS", "Events", "expiration", "Alert ID"}
	if printMachine {
		header = append(header, "Machine")
	}
	t.SetHeaders(header...)

	for _, alertItem := range *alerts {
		for _, decisionItem := range alertItem.Decisions {
			if *alertItem.Simulated {
				*decisionItem.Type = fmt.Sprintf("(simul)%s", *decisionItem.Type)
			}
			row := []string{
				strconv.Itoa(int(decisionItem.ID)),
				*decisionItem.Origin,
				*decisionItem.Scope + ":" + *decisionItem.Value,
				*decisionItem.Scenario,
				*decisionItem.Type,
				alertItem.Source.Cn,
				alertItem.Source.AsNumber + " " + alertItem.Source.AsName,
				strconv.Itoa(int(*alertItem.EventsCount)),
				*decisionItem.Duration,
				strconv.Itoa(int(alertItem.ID)),
			}

			if printMachine {
				row = append(row, alertItem.MachineID)
			}

			t.AddRow(row...)
		}
	}
	t.Render()
}
