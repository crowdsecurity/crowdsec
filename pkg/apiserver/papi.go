package apiserver

import (
	"time"

	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/jcuga/golongpoll/client"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	PAPI_PULL_KEY = "papi:last_pull"

	addDecisionOrder    = "add_decision"
	deleteDecisionOrder = "delete_decision"
)

func PapiError(err error) bool {
	log.Warningf("PAPI/ERROR : %s", err)
	return true
}

type Header struct {
	Operation string
	Timestamp time.Time
	Message   string
	UUID      string
}

type Message struct {
	Header *Header
	Data   interface{}
}

type OperationChannel struct {
	AddAlertChannel       chan []*models.Alert
	DeleteDecisionChannel chan []*models.Decision
}

type Papi struct {
	URL      string
	Client   *client.Client
	DBClient *database.Client
	Channels *OperationChannel
}

func NewPAPI(centralApi *apic, DBClient *database.Client) (*Papi, error) {

	if centralApi.apiClient.PapiURL == nil {
		return &Papi{}, errors.New("PAPI URL is nil")
	}
	longPollClient, err := client.NewClient(client.ClientOptions{
		SubscribeUrl:   *centralApi.apiClient.PapiURL,
		Category:       "some-category", //what should we do with this one ?
		HttpClient:     centralApi.apiClient.GetClient(),
		OnFailure:      PapiError,
		LoggingEnabled: true,
	})
	if err != nil {
		return &Papi{}, errors.Wrap(err, "failed to create PAPI client")
	}

	channels := &OperationChannel{
		AddAlertChannel:       centralApi.AlertsAddChan,
		DeleteDecisionChannel: centralApi.DecisionDeleteChan,
	}

	papi := &Papi{
		URL:      centralApi.apiClient.PapiURL.String(),
		Client:   longPollClient,
		DBClient: DBClient,
		Channels: channels,
	}

	return papi, nil
}

//PullPAPI is the long polling client for real-time decisions from PAPI
func (p *Papi) Pull() error {

	defer types.CatchPanic("lapi/PullPAPI")
	log.Infof("Starting Polling API Pull")

	lastTimestamp := time.Now().UTC()
	lastTimestampStr, err := p.DBClient.GetConfigItem(PAPI_PULL_KEY)
	if err != nil {
		log.Warningf("failed to get last timestamp for papi pull: %s", err)
		//return errors.Wrap(err, "failed to get last timestamp for papi pull")
	}
	//value doesn't exist, it's first time we're pulling
	if lastTimestampStr == nil {
		binTime, err := lastTimestamp.MarshalText()
		if err != nil {
			return errors.Wrap(err, "failed to marshal last timestamp")
		}
		p.DBClient.SetConfigItem(PAPI_PULL_KEY, string(binTime))
	} else {
		if err := lastTimestamp.UnmarshalText([]byte(*lastTimestampStr)); err != nil {
			return errors.Wrap(err, "failed to unmarshal last timestamp")
		}
	}

	log.Infof("Starting PAPI pull (since:%s)", lastTimestamp)
	for event := range p.Client.Start(lastTimestamp) {
		//update last timestamp in database
		newTime := time.Now().UTC()
		binTime, err := newTime.MarshalText()
		if err != nil {
			return errors.Wrap(err, "failed to marshal last timestamp")
		}

		message, ok := event.Data.(Message)
		if !ok {
			return fmt.Errorf("polling papi message format is not compatible")
		}

		switch message.Header.Operation {
		case deleteDecisionOrder:
			UUIDs, ok := message.Data.([]string)
			if !ok {
				log.Errorf("message for '%s' contains bad data format", message.Header.Operation)
				continue
			}
			filter := make(map[string][]string)
			filter["uuid"] = UUIDs
			_, deletedDecisions, err := p.DBClient.SoftDeleteDecisionsWithFilter(filter)
			if err != nil {
				log.Errorf("unable to delete decisions %+v : %s", UUIDs, err)
				continue
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

		case addDecisionOrder:
			alert, ok := message.Data.(models.Alert)
			if !ok {
				log.Errorf("message for '%s' contains bad alert format", message.Header.Operation)
				continue
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
			alert.Source.Scope = types.StrPtr(SCOPE_CAPI)
			alert.Source.Value = types.StrPtr("")
			//use a different method : alert and/or decision might already be partially present in the database
			_, err = p.DBClient.CreateOrUpdateAlert("", &alert)
			if err != nil {
				log.Errorf("Failed to create alerts in DB: %s", err)
			} else {
				p.Channels.AddAlertChannel <- []*models.Alert{&alert}
			}

		default:
			log.Errorf("unknown message operation '%s'", message.Header.Operation)
			continue
		}

		if err := p.DBClient.SetConfigItem(PAPI_PULL_KEY, string(binTime)); err != nil {
			return errors.Wrap(err, "failed to update last timestamp")
		} else {
			log.Debugf("set last timestamp to %s", newTime)
		}
	}
	return nil
}
