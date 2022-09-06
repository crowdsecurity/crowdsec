package apiserver

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func DecisionCmd(message *Message, p *Papi) error {
	switch message.Header.OperationCmd {
	case "delete":
		data, err := json.Marshal(message.Data)
		if err != nil {
			return err
		}
		UUIDs := make([]string, 0)

		if err := json.Unmarshal(data, UUIDs); err != nil {
			return fmt.Errorf("message for '%s' contains bad data format", message.Header.OperationType)
		}

		filter := make(map[string][]string)
		filter["uuid"] = UUIDs
		_, deletedDecisions, err := p.DBClient.SoftDeleteDecisionsWithFilter(filter)
		if err != nil {
			return fmt.Errorf("unable to delete decisions %+v : %s", UUIDs, err)
		}
		decisions := make([]*models.Decision, 0)
		for _, deletedDecision := range deletedDecisions {
			dec := &models.Decision{
				UUID:     deletedDecision.UUID,
				Origin:   &deletedDecision.Origin,
				Scenario: &deletedDecision.Scenario,
				Scope:    &deletedDecision.Scope,
				Value:    &deletedDecision.Value,
				ID:       int64(deletedDecision.ID),
				Until:    deletedDecision.Until.String(),
				Type:     &deletedDecision.Type,
			}
			decisions = append(decisions, dec)
		}
		p.Channels.DeleteDecisionChannel <- decisions
	default:
		return fmt.Errorf("unknown command '%s' for operation type '%s'", message.Header.OperationCmd, message.Header.OperationType)
	}

	return nil
}

func AlertCmd(message *Message, p *Papi) error {
	switch message.Header.OperationCmd {
	case "add":
		data, err := json.Marshal(message.Data)
		if err != nil {
			return err
		}
		alert := &models.Alert{}

		if err := json.Unmarshal(data, alert); err != nil {
			return fmt.Errorf("message for '%s' contains bad alert format", message.Header.OperationType)
		}

		log.Infof("Received order %s from PAPI (%d decisions)", alert.UUID, len(alert.Decisions))

		/*Fix the alert with missing mandatory items*/
		alert.StartAt = types.StrPtr(time.Now().UTC().Format(time.RFC3339))
		alert.StopAt = types.StrPtr(time.Now().UTC().Format(time.RFC3339))
		alert.EventsCount = types.Int32Ptr(0)
		alert.Capacity = types.Int32Ptr(0)
		alert.Leakspeed = types.StrPtr("")
		alert.Simulated = types.BoolPtr(false)
		alert.ScenarioHash = types.StrPtr("")
		alert.ScenarioVersion = types.StrPtr("")
		alert.Message = types.StrPtr("")
		alert.Scenario = types.StrPtr("")
		alert.Source = &models.Source{}
		alert.Source.Scope = types.StrPtr(SCOPE_PAPI)
		alert.Source.Value = &message.Header.Source.User
		alert.Scenario = &message.Header.Message

		for _, decision := range alert.Decisions {
			if *decision.Scenario == "" {
				decision.Scenario = &message.Header.Message
			}
		}

		//use a different method : alert and/or decision might already be partially present in the database
		_, err = p.DBClient.CreateOrUpdateAlert("", alert)
		if err != nil {
			log.Errorf("Failed to create alerts in DB: %s", err)
		} else {
			p.Channels.AddAlertChannel <- []*models.Alert{alert}
		}

	default:
		return fmt.Errorf("unknown command '%s' for operation type '%s'", message.Header.OperationCmd, message.Header.OperationType)
	}

	return nil
}
