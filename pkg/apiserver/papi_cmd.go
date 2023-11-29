package apiserver

import (
	"encoding/json"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/ptr"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/modelscapi"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type deleteDecisions struct {
	UUID      string   `json:"uuid"`
	Decisions []string `json:"decisions"`
}

type blocklistLink struct {
	// blocklist name
	Name string `json:"name"`
	// blocklist url
	Url string `json:"url"`
	// blocklist remediation
	Remediation string `json:"remediation"`
	// blocklist scope
	Scope string `json:"scope,omitempty"`
	// blocklist duration
	Duration string `json:"duration,omitempty"`
}

type forcePull struct {
	Blocklist *blocklistLink `json:"blocklist,omitempty"`
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
			return fmt.Errorf("message for '%s' contains bad alert format: %w", message.Header.OperationType, err)
		}

		log.Infof("Received order %s from PAPI (%d decisions)", alert.UUID, len(alert.Decisions))

		/*Fix the alert with missing mandatory items*/
		if alert.StartAt == nil || *alert.StartAt == "" {
			log.Warnf("Alert %d has no StartAt, setting it to now", alert.ID)
			alert.StartAt = ptr.Of(time.Now().UTC().Format(time.RFC3339))
		}
		if alert.StopAt == nil || *alert.StopAt == "" {
			log.Warnf("Alert %d has no StopAt, setting it to now", alert.ID)
			alert.StopAt = ptr.Of(time.Now().UTC().Format(time.RFC3339))
		}
		alert.EventsCount = ptr.Of(int32(0))
		alert.Capacity = ptr.Of(int32(0))
		alert.Leakspeed = ptr.Of("")
		alert.Simulated = ptr.Of(false)
		alert.ScenarioHash = ptr.Of("")
		alert.ScenarioVersion = ptr.Of("")
		alert.Message = ptr.Of("")
		alert.Scenario = ptr.Of("")
		alert.Source = &models.Source{}

		//if we're setting Source.Scope to types.ConsoleOrigin, it messes up the alert's value
		if len(alert.Decisions) >= 1 {
			alert.Source.Scope = alert.Decisions[0].Scope
			alert.Source.Value = alert.Decisions[0].Value
		} else {
			log.Warningf("No decision found in alert for Polling API (%s : %s)", message.Header.Source.User, message.Header.Message)
			alert.Source.Scope = ptr.Of(types.ConsoleOrigin)
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
		data, err := json.Marshal(message.Data)
		if err != nil {
			return err
		}
		forcePullMsg := forcePull{}
		if err := json.Unmarshal(data, &forcePullMsg); err != nil {
			return fmt.Errorf("message for '%s' contains bad data format: %s", message.Header.OperationType, err)
		}

		if forcePullMsg.Blocklist == nil {
			log.Infof("Received force_pull command from PAPI, pulling community and 3rd-party blocklists")
			err = p.apic.PullTop(true)
			if err != nil {
				return fmt.Errorf("failed to force pull operation: %s", err)
			}
		} else {
			log.Infof("Received force_pull command from PAPI, pulling blocklist %s", forcePullMsg.Blocklist.Name)
			err = p.apic.PullBlocklist(&modelscapi.BlocklistLink{
				Name:        &forcePullMsg.Blocklist.Name,
				URL:         &forcePullMsg.Blocklist.Url,
				Remediation: &forcePullMsg.Blocklist.Remediation,
				Scope:       &forcePullMsg.Blocklist.Scope,
				Duration:    &forcePullMsg.Blocklist.Duration,
			}, true)
			if err != nil {
				return fmt.Errorf("failed to force pull operation: %s", err)
			}
		}

	default:
		return fmt.Errorf("unknown command '%s' for operation type '%s'", message.Header.OperationCmd, message.Header.OperationType)
	}
	return nil
}
