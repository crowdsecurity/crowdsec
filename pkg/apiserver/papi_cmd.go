package apiserver

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

type deleteDecisions struct {
	UUID      string   `json:"uuid"`
	Decisions []string `json:"decisions"`
}

func DecisionCmd(message *Message, p *Papi) error {
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

		/*

						 Header: (*apiserver.Header)(0xc000324000)({
						  OperationType: (string) (len=5) "alert",
						  OperationCmd: (string) (len=3) "add",
						  Timestamp: (time.Time) 2023-01-16 13:32:48.97 +0000 UTC,
						  Message: (string) (len=18) "order from papicli",
						  UUID: (string) (len=36) "e3f303af-d9fe-4429-b0e0-02322c1f9008",
						  Source: (*apiserver.Source)(0xc000508320)({
						   User: (string) (len=7) "papicli"
						  }),
						  Destination: (string) ""
						 }),
						 Data: (map[string]interface {}) (len=15) {
						  (string) (len=10) "created_at": (string) (len=20) "0001-01-01T00:00:00Z",
						  (string) (len=6) "labels": (interface {}) <nil>,
						  (string) (len=6) "source": (interface {}) <nil>,
						  (string) (len=8) "start_at": (string) (len=30) "2023-01-16T13:32:48.970167901Z",
						  (string) (len=7) "stop_at": (string) (len=30) "2023-01-16T13:32:48.970167991Z",
						  (string) (len=8) "capacity": (interface {}) <nil>,
						  (string) (len=8) "scenario": (string) (len=4) "test",
						  (string) (len=13) "scenario_hash": (interface {}) <nil>,
						  (string) (len=16) "scenario_version": (interface {}) <nil>,
						  (string) (len=4) "uuid": (string) (len=36) "dcb90fb2-38e5-44e0-bd23-eecb84aa0213",
						  (string) (len=9) "decisions": ([]interface {}) (len=1 cap=1) {
						   (map[string]interface {}) (len=8) {
						    (string) (len=8) "duration": (string) (len=2) "4h",
						    (string) (len=6) "origin": (string) (len=7) "console",
						    (string) (len=8) "scenario": (string) (len=16) "papicli-scenario",
						    (string) (len=5) "scope": (string) (len=2) "Ip",
						    (string) (len=4) "type": (string) (len=3) "ban",
						    (string) (len=5) "until": (string) (len=25) "2023-01-16T18:32:48+01:00",
						    (string) (len=5) "value": (string) (len=15) "156.234.143.212",
						    (string) (len=4) "uuid": (string) (len=36) "107b73bd-d1aa-4b23-a608-925d1f1edce3"
						   }
						  },
						  (string) (len=12) "events_count": (interface {}) <nil>,
						  (string) (len=9) "leakspeed": (interface {}) <nil>,
						  (string) (len=7) "message": (interface {}) <nil>,
						  (string) (len=9) "simulated": (interface {}) <nil>
						 }
						})


			▶ ./cscli -c dev.yaml decisions list --origin console
			╭──────┬─────────┬────────────────────┬──────────────────┬────────┬─────────┬────┬────────┬────────────────────┬──────────╮
			│  ID  │ Source  │    Scope:Value     │      Reason      │ Action │ Country │ AS │ Events │     expiration     │ Alert ID │
			├──────┼─────────┼────────────────────┼──────────────────┼────────┼─────────┼────┼────────┼────────────────────┼──────────┤
			│ 9543 │ console │ Ip:196.110.219.61  │ papicli-scenario │ ban    │         │    │ 0      │ 3h57m33.546296102s │ 27       │
			│ 9544 │ console │ Ip:172.212.110.236 │ papicli-scenario │ ban    │         │    │ 0      │ 3h57m33.54629506s  │ 27       │



			Source: 'console' or 'user@console' ?
			Reason: 'because blah' and/or username ?
			Merge : Country + AS ?


			▶ ./cscli -c dev.yaml alerts list --origin console
			╭────┬─────────────────┬────────────────────┬─────────┬────┬───────────┬───────────────────────────────╮
			│ ID │      value      │       reason       │ country │ as │ decisions │          created_at           │
			├────┼─────────────────┼────────────────────┼─────────┼────┼───────────┼───────────────────────────────┤
			│ 27 │ console:papicli │ order from papicli │         │    │ ban:3     │ 2023-01-16 14:27:46 +0000 UTC │
			│ 26 │ console:papicli │ order from papicli │         │    │ ban:3     │ 2023-01-16 13:37:36 +0000 UTC │
			│ 22 │ Ip:1.2.3.4      │ manual 'ban' from 'test' │         │    │ ban:1     │ 2023-01-16 13:13:54 +0000 UTC │


			-> Add Source (cscli/console/agent..)
			-> Value isn't consistent (ip sometimes, message ?)

			-> Merge country+as ?

			MULTI ADD :
			▶ ./cscli -c dev.yaml alerts list --origin cscli-import
			╭────┬───────┬────────────┬─────────┬────┬───────────┬───────────────────────────────╮
			│ ID │ value │   reason   │ country │ as │ decisions │          created_at           │
			├────┼───────┼────────────┼─────────┼────┼───────────┼───────────────────────────────┤
			│ 28 │       │ add: 2 IPs │         │    │ ban:2     │ 2023-01-16 14:40:27 +0000 UTC │

			Value: Multiple IPs (2)
			Reason: Import from decisions.csv


		*/

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

		//if we're setting Source.Scope to SCOPE_PAPI, it messes up the alert's value
		if len(alert.Decisions) >= 1 {
			alert.Source.Scope = alert.Decisions[0].Scope
			alert.Source.Value = alert.Decisions[0].Value
		} else {
			log.Warningf("No decision found in alert for Polling API (%s : %s)", message.Header.Source.User, message.Header.Message)
			alert.Source.Scope = types.StrPtr(SCOPE_PAPI)
			alert.Source.Value = &message.Header.Source.User
		}
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

// func GenSourceFromAlert(alert *models.Alert) string {

// 	//if there is more than one decision, just get the type and count : "2 IP decisions"
// 	if len(alert.Decisions) > 1 {
// 		//get the type of decision
// 		decType := alert.Decisions[0].Scope
// 		//get the count of decisions
// 		decCount := len(alert.Decisions)
// 		return fmt.Sprintf("%d %s decisions", decCount, *decType)
// 	}
// 	//otherwise, get the value of the decision
// 	if len(alert.Decisions) == 1 {
// 		val := ""
// 		scope := ""

// 		if alert.Decisions[0].Value != nil {
// 			val = *alert.Decisions[0].Value
// 		}
// 		if alert.Decisions[0].Scope != nil {
// 			scope = *alert.Decisions[0].Scope
// 		}
// 		return fmt.Sprintf("%s:%s", scope, val)
// 	}
// 	//no decisions ?
// 	return "no decisions"
// }
