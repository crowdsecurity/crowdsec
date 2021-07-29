package main

import "github.com/crowdsecurity/crowdsec/pkg/models"

func main() {
	c := models.Alert{}
	c.Decisions = append(c.Decisions, &models.Decision{})
}
