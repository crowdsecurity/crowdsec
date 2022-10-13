package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func alertsTable(out io.Writer, alerts *models.GetAlertsResponse, printMachine bool) {
	t := newTable(out)
	t.SetRowLines(false)
	header := []string{"ID", "value", "reason", "country", "as", "decisions", "created_at"}
	if printMachine {
		header = append(header, "machine")
	}
	t.SetHeaders(header...)

	for _, alertItem := range *alerts {
		displayVal := *alertItem.Source.Scope
		if *alertItem.Source.Value != "" {
			displayVal += ":" + *alertItem.Source.Value
		}

		row := []string{
			strconv.Itoa(int(alertItem.ID)),
			displayVal,
			*alertItem.Scenario,
			alertItem.Source.Cn,
			alertItem.Source.AsNumber + " " + alertItem.Source.AsName,
			DecisionsFromAlert(alertItem),
			*alertItem.StartAt,
		}

		if printMachine {
			row = append(row, alertItem.MachineID)
		}

		t.AddRow(row...)
	}

	t.Render()
}

func alertDecisionsTable(out io.Writer, alert *models.Alert) {
	foundActive := false
	t := newTable(out)
	t.SetRowLines(false)
	t.SetHeaders("ID", "scope:value", "action", "expiration", "created_at")
	for _, decision := range alert.Decisions {
		parsedDuration, err := time.ParseDuration(*decision.Duration)
		if err != nil {
			log.Errorf(err.Error())
		}
		expire := time.Now().UTC().Add(parsedDuration)
		if time.Now().UTC().After(expire) {
			continue
		}
		foundActive = true
		scopeAndValue := *decision.Scope
		if *decision.Value != "" {
			scopeAndValue += ":" + *decision.Value
		}
		t.AddRow(
			strconv.Itoa(int(decision.ID)),
			scopeAndValue,
			*decision.Type,
			*decision.Duration,
			alert.CreatedAt,
		)
	}
	if foundActive {
		fmt.Printf(" - Active Decisions  :\n")
		t.Render() // Send output
	}
}

func alertEventTable(out io.Writer, event *models.Event) {
	fmt.Fprintf(out, "\n- Date: %s\n", *event.Timestamp)

	t := newTable(out)
	t.SetHeaders("Key", "Value")
	sort.Slice(event.Meta, func(i, j int) bool {
		return event.Meta[i].Key < event.Meta[j].Key
	})

	for _, meta := range event.Meta {
		t.AddRow(
			meta.Key,
			meta.Value,
		)
	}

	t.Render() // Send output
}
