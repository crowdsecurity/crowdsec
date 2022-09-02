package apiserver

import (
	"context"
	"net/url"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/jcuga/golongpoll/client"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

var (
	SyncInterval = time.Second * 10
)

const (
	PapiPullKey = "papi:last_pull"

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

type OperationChannels struct {
	AddAlertChannel       chan []*models.Alert
	DeleteDecisionChannel chan []*models.Decision
}

type Papi struct {
	URL           string
	Client        *client.Client
	DBClient      *database.Client
	apiClient     *apiclient.ApiClient
	Channels      *OperationChannels
	mu            sync.Mutex
	pullTomb      tomb.Tomb
	syncTomb      tomb.Tomb
	SyncInterval  time.Duration
	consoleConfig *csconfig.ConsoleConfig
}

func NewPAPI(apic *apic, dbClient *database.Client, consoleConfig *csconfig.ConsoleConfig) (*Papi, error) {
	PapiURL, err := url.Parse(types.PAPIBaseURL)
	if err != nil {
		return nil, errors.Wrapf(err, "while parsing '%s'", types.PAPIBaseURL)
	}

	longPollClient, err := client.NewClient(client.ClientOptions{
		SubscribeUrl:   *PapiURL,
		Category:       "some-category", //what should we do with this one ?
		HttpClient:     apic.apiClient.GetClient(),
		OnFailure:      PapiError,
		LoggingEnabled: true,
	})
	if err != nil {
		return &Papi{}, errors.Wrap(err, "failed to create PAPI client")
	}

	channels := &OperationChannels{
		AddAlertChannel:       apic.AlertsAddChan,
		DeleteDecisionChannel: make(chan []*models.Decision),
	}

	papi := &Papi{
		URL:          PapiURL.String(),
		Client:       longPollClient,
		DBClient:     dbClient,
		Channels:     channels,
		SyncInterval: SyncInterval,
		mu:           sync.Mutex{},
		pullTomb:     tomb.Tomb{},
		syncTomb:     tomb.Tomb{},
		apiClient:    apic.apiClient,
	}

	return papi, nil
}

//PullPAPI is the long polling client for real-time decisions from PAPI
func (p *Papi) Pull() error {

	defer types.CatchPanic("lapi/PullPAPI")
	log.Infof("Starting Polling API Pull")

	lastTimestamp := time.Now().UTC()
	lastTimestampStr, err := p.DBClient.GetConfigItem(PapiPullKey)
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
		p.DBClient.SetConfigItem(PapiPullKey, string(binTime))
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
			log.Infof("MESSAGE: %+v", event.Data)
			log.Errorf("polling papi message format is not compatible")
			// do we want to continue or exit ?
			continue
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

		if err := p.DBClient.SetConfigItem(PapiPullKey, string(binTime)); err != nil {
			return errors.Wrap(err, "failed to update last timestamp")
		} else {
			log.Debugf("set last timestamp to %s", newTime)
		}
	}
	return nil
}

func (p *Papi) SyncDecisions() error {
	defer types.CatchPanic("lapi/syncDecisionsToCAPI")

	var cache models.AddSignalsRequestItemDecisions
	ticker := time.NewTicker(p.SyncInterval)
	log.Infof("Start decisions sync to CrowdSec Central API (interval: %s)", PushInterval)

	for {
		select {
		case <-p.syncTomb.Dying(): // if one apic routine is dying, do we kill the others?
			p.pullTomb.Kill(nil)
			log.Infof("sync decisions tomb is dying, sending cache (%d elements) before exiting", len(cache))
			if len(cache) == 0 {
				return nil
			}
			go p.SendDeletedDecisions(&cache)
			return nil
		case <-ticker.C:
			if len(cache) > 0 {
				p.mu.Lock()
				cacheCopy := cache
				cache = make([]*models.AddSignalsRequestItemDecisionsItem, 0)
				p.mu.Unlock()
				log.Infof("sync decisions: %d deleted decisions to push", len(cacheCopy))
				go p.SendDeletedDecisions(&cacheCopy)
			}
		case deletedDecisions := <-p.Channels.DeleteDecisionChannel:

			if p.consoleConfig.ShareManualDecisions != nil && *p.consoleConfig.ShareManualDecisions {
				var tmpDecisions []*models.AddSignalsRequestItemDecisionsItem
				for _, decision := range deletedDecisions {

					x := &models.AddSignalsRequestItemDecisionsItem{
						Duration: types.StrPtr(*decision.Duration),
						ID:       new(int64),
						Origin:   types.StrPtr(*decision.Origin),
						Scenario: types.StrPtr(*decision.Scenario),
						Scope:    types.StrPtr(*decision.Scope),
						Type:     types.StrPtr(*decision.Type),
						Until:    decision.Until,
						Value:    types.StrPtr(*decision.Value),
					}
					if decision.Simulated != nil {
						x.Simulated = *decision.Simulated
					}
					tmpDecisions = append(tmpDecisions, x)
				}

				p.mu.Lock()
				cache = append(cache, tmpDecisions...)
				p.mu.Unlock()
			}
		}
	}
}

func (p *Papi) SendDeletedDecisions(cacheOrig *models.AddSignalsRequestItemDecisions) {

	var cache []*models.AddSignalsRequestItemDecisionsItem = *cacheOrig
	var send models.AddSignalsRequestItemDecisions

	bulkSize := 50
	pageStart := 0
	pageEnd := bulkSize

	for {

		if pageEnd >= len(cache) {
			send = cache[pageStart:]
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _, err := p.apiClient.DecisionDelete.Add(ctx, &send)
			if err != nil {
				log.Errorf("Error while sending final chunk to central API : %s", err)
				return
			}
			break
		}
		send = cache[pageStart:pageEnd]
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, err := p.apiClient.DecisionDelete.Add(ctx, &send)
		if err != nil {
			//we log it here as well, because the return value of func might be discarded
			log.Errorf("Error while sending chunk to central API : %s", err)
		}
		pageStart += bulkSize
		pageEnd += bulkSize
	}
}
