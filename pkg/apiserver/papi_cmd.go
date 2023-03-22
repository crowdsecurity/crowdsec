package apiserver

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type deleteDecisions struct {
	UUID      string   `json:"uuid"`
	Decisions []string `json:"decisions"`
}

func DecisionCmd(message *Message, p *Papi, sync bool) error {
	switch message.Header.OperationCmd {
	case "delete":

		data, err := json.Marshal(message.Data)
		if err != nil {
			return err
		}
		UUIDs := make([]string, 0)
		deleteDecisionMsg := deleteDecisions{
			Decisions: make([]string, 0),
		}
		if err := json.Unmarshal(data, &deleteDecisionMsg); err != nil {
			return fmt.Errorf("message for '%s' contains bad data format: %s", message.Header.OperationType, err)
		}

		UUIDs = append(UUIDs, deleteDecisionMsg.Decisions...)
		log.Infof("Decisions UUIDs to remove: %+v", UUIDs)

		filter := make(map[string][]string)
		filter["uuid"] = UUIDs
		_, deletedDecisions, err := p.DBClient.SoftDeleteDecisionsWithFilter(filter)
		if err != nil {
			return fmt.Errorf("unable to delete decisions %+v : %s", UUIDs, err)
		}
		decisions := make([]*models.Decision, 0)
		for _, deletedDecision := range deletedDecisions {
			log.Infof("Decision from '%s' for '%s' (%s) has been deleted", deletedDecision.Origin, deletedDecision.Value, deletedDecision.Type)
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

func AlertCmd(message *Message, p *Papi, sync bool) error {
	switch message.Header.OperationCmd {
	case "add":
		data, err := json.Marshal(message.Data)
		if err != nil {
			return err
		}
		alert := &models.Alert{}

		if err := json.Unmarshal(data, alert); err != nil {
			return errors.Wrapf(err, "message for '%s' contains bad alert format", message.Header.OperationType)
		}

		log.Infof("Received order %s from PAPI (%d decisions)", alert.UUID, len(alert.Decisions))

		/*Fix the alert with missing mandatory items*/
		if alert.StartAt == nil || *alert.StartAt == "" {
			log.Warnf("Alert %d has no StartAt, setting it to now", alert.ID)
			alert.StartAt = types.StrPtr(time.Now().UTC().Format(time.RFC3339))
		}
		if alert.StopAt == nil || *alert.StopAt == "" {
			log.Warnf("Alert %d has no StopAt, setting it to now", alert.ID)
			alert.StopAt = types.StrPtr(time.Now().UTC().Format(time.RFC3339))
		}
		alert.EventsCount = types.Int32Ptr(0)
		alert.Capacity = types.Int32Ptr(0)
		alert.Leakspeed = types.StrPtr("")
		alert.Simulated = types.BoolPtr(false)
		alert.ScenarioHash = types.StrPtr("")
		alert.ScenarioVersion = types.StrPtr("")
		alert.Message = types.StrPtr("")
		alert.Scenario = types.StrPtr("")
		alert.Source = &models.Source{}

		//if we're setting Source.Scope to types.ConsoleOrigin, it messes up the alert's value
		if len(alert.Decisions) >= 1 {
			alert.Source.Scope = alert.Decisions[0].Scope
			alert.Source.Value = alert.Decisions[0].Value
		} else {
			log.Warningf("No decision found in alert for Polling API (%s : %s)", message.Header.Source.User, message.Header.Message)
			alert.Source.Scope = types.StrPtr(types.ConsoleOrigin)
			alert.Source.Value = &message.Header.Source.User
		}
		alert.Scenario = &message.Header.Message

		for _, decision := range alert.Decisions {
			if *decision.Scenario == "" {
				decision.Scenario = &message.Header.Message
			}
			log.Infof("Adding decision for '%s' with UUID: %s", *decision.Value, decision.UUID)
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

func ManagementCmd(message *Message, p *Papi, sync bool) error {
	if sync {
		log.Infof("Ignoring management command from PAPI in sync mode")
		return nil
	}
	switch message.Header.OperationCmd {
	case "reauth":
		log.Infof("Received reauth command from PAPI, resetting token")
		p.apiClient.GetClient().Transport.(*apiclient.JWTTransport).ResetToken()
	case "force_pull":
		log.Infof("Received force_pull command from PAPI, pulling community and 3rd-party blocklists")
		err := p.apic.PullTop(true)
		if err != nil {
			return fmt.Errorf("failed to force pull operation: %s", err)
		}
	default:
		return fmt.Errorf("unknown command '%s' for operation type '%s'", message.Header.OperationCmd, message.Header.OperationType)
	}
	return nil
}
