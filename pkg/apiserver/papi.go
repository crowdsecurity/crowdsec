package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/longpollclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

var (
	SyncInterval = time.Second * 10
)

const (
	PapiPullKey = "papi:last_pull"
)

var (
	operationMap = map[string]func(*Message, *Papi) error{
		"decision": DecisionCmd,
		"alert":    AlertCmd,
	}
)

type Header struct {
	OperationType string    `json:"operation_type"`
	OperationCmd  string    `json:"operation_cmd"`
	Timestamp     time.Time `json:"timestamp"`
	Message       string    `json:"message"`
	UUID          string    `json:"uuid"`
	Source        *Source   `json:"source"`
	Destination   string    `json:"destination"`
}

type Source struct {
	User string `json:"user"`
}

type Message struct {
	Header *Header
	Data   interface{} `json:"data"`
}

type OperationChannels struct {
	AddAlertChannel       chan []*models.Alert
	DeleteDecisionChannel chan []*models.Decision
}

type Papi struct {
	URL           string
	Client        *longpollclient.LongPollClient
	DBClient      *database.Client
	apiClient     *apiclient.ApiClient
	Channels      *OperationChannels
	mu            sync.Mutex
	pullTomb      tomb.Tomb
	syncTomb      tomb.Tomb
	SyncInterval  time.Duration
	consoleConfig *csconfig.ConsoleConfig
	Logger        *log.Entry
}

func NewPAPI(apic *apic, dbClient *database.Client, consoleConfig *csconfig.ConsoleConfig, logLevel log.Level) (*Papi, error) {

	logger := logrus.New()
	if err := types.ConfigureLogger(logger); err != nil {
		return &Papi{}, fmt.Errorf("creating papi logger: %s", err)
	}
	logger.SetLevel(logLevel)

	longPollClient, err := longpollclient.NewLongPollClient(longpollclient.LongPollClientConfig{
		Url:        *apic.apiClient.PapiURL,
		Logger:     logger,
		HttpClient: apic.apiClient.GetClient(),
	})

	if err != nil {
		return &Papi{}, errors.Wrap(err, "failed to create PAPI client")
	}

	channels := &OperationChannels{
		AddAlertChannel:       apic.AlertsAddChan,
		DeleteDecisionChannel: make(chan []*models.Decision),
	}

	papi := &Papi{
		URL:           apic.apiClient.PapiURL.String(),
		Client:        longPollClient,
		DBClient:      dbClient,
		Channels:      channels,
		SyncInterval:  SyncInterval,
		mu:            sync.Mutex{},
		pullTomb:      tomb.Tomb{},
		syncTomb:      tomb.Tomb{},
		apiClient:     apic.apiClient,
		consoleConfig: consoleConfig,
		Logger:        logger.WithFields(log.Fields{"interval": SyncInterval.Seconds(), "source": "papi"}),
	}

	return papi, nil
}

// PullPAPI is the long polling client for real-time decisions from PAPI
func (p *Papi) Pull() error {

	defer types.CatchPanic("lapi/PullPAPI")
	p.Logger.Infof("Starting Polling API Pull")

	lastTimestamp := time.Time{}
	lastTimestampStr, err := p.DBClient.GetConfigItem(PapiPullKey)
	if err != nil {
		p.Logger.Warningf("failed to get last timestamp for papi pull: %s", err)
	}
	//value doesn't exist, it's first time we're pulling
	if lastTimestampStr == nil {
		binTime, err := lastTimestamp.MarshalText()
		if err != nil {
			return errors.Wrap(err, "failed to marshal last timestamp")
		}
		if err := p.DBClient.SetConfigItem(PapiPullKey, string(binTime)); err != nil {
			p.Logger.Errorf("error setting papi pull last key: %s", err)
		} else {
			p.Logger.Debugf("config item '%s' set in database with value '%s'", PapiPullKey, string(binTime))
		}
	} else {
		if err := lastTimestamp.UnmarshalText([]byte(*lastTimestampStr)); err != nil {
			return errors.Wrap(err, "failed to unmarshal last timestamp")
		}
	}

	p.Logger.Infof("Starting PAPI pull (since:%s)", lastTimestamp)
	for event := range p.Client.Start(lastTimestamp) {
		//update last timestamp in database
		newTime := time.Now().UTC()
		binTime, err := newTime.MarshalText()
		if err != nil {
			return errors.Wrap(err, "failed to marshal last timestamp")
		}
		p.Logger.Debugf("message received: %+v", event.Data)
		message := &Message{}
		if err := json.Unmarshal([]byte(event.Data), message); err != nil {
			p.Logger.Errorf("polling papi message format is not compatible: %+v: %s", event.Data, err)
			// do we want to continue or exit ?
			continue
		}

		if message.Header == nil {
			p.Logger.Errorf("no header in message, skipping")
			continue
		}

		if message.Header.Source == nil {
			p.Logger.Errorf("no source user in header message, skipping")
			continue
		}

		if operationFunc, ok := operationMap[message.Header.OperationType]; ok {
			p.Logger.Debugf("Calling operation '%s'", message.Header.OperationType)
			err := operationFunc(message, p)
			if err != nil {
				p.Logger.Errorf("'%s %s failed: %s", message.Header.OperationType, message.Header.OperationCmd, err)
				continue
			}
		} else {
			p.Logger.Errorf("operation '%s' unknown, continue", message.Header.OperationType)
			continue
		}

		if err := p.DBClient.SetConfigItem(PapiPullKey, string(binTime)); err != nil {
			return errors.Wrap(err, "failed to update last timestamp")
		} else {
			p.Logger.Debugf("set last timestamp to %s", newTime)
		}

	}
	return nil
}

func (p *Papi) SyncDecisions() error {
	defer types.CatchPanic("lapi/syncDecisionsToCAPI")

	var cache models.DecisionsDeleteRequest
	ticker := time.NewTicker(p.SyncInterval)
	p.Logger.Infof("Start decisions sync to CrowdSec Central API (interval: %s)", p.SyncInterval)

	for {
		select {
		case <-p.syncTomb.Dying(): // if one apic routine is dying, do we kill the others?
			p.Logger.Infof("sync decisions tomb is dying, sending cache (%d elements) before exiting", len(cache))
			if len(cache) == 0 {
				return nil
			}
			go p.SendDeletedDecisions(&cache)
			return nil
		case <-ticker.C:
			if len(cache) > 0 {
				p.mu.Lock()
				cacheCopy := cache
				cache = make([]models.DecisionsDeleteRequestItem, 0)
				p.mu.Unlock()
				p.Logger.Infof("sync decisions: %d deleted decisions to push", len(cacheCopy))
				go p.SendDeletedDecisions(&cacheCopy)
			}
		case deletedDecisions := <-p.Channels.DeleteDecisionChannel:
			if (p.consoleConfig.ShareManualDecisions != nil && *p.consoleConfig.ShareManualDecisions) || (p.consoleConfig.ReceiveDecisions != nil && *p.consoleConfig.ReceiveDecisions) {
				var tmpDecisions []models.DecisionsDeleteRequestItem
				p.Logger.Debugf("%d decisions deletion to add in cache", len(deletedDecisions))
				for _, decision := range deletedDecisions {
					tmpDecisions = append(tmpDecisions, models.DecisionsDeleteRequestItem(decision.UUID))
				}
				p.mu.Lock()
				cache = append(cache, tmpDecisions...)
				p.mu.Unlock()
			}
		}
	}
}

func (p *Papi) SendDeletedDecisions(cacheOrig *models.DecisionsDeleteRequest) {

	var cache []models.DecisionsDeleteRequestItem = *cacheOrig
	var send models.DecisionsDeleteRequest

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
				p.Logger.Errorf("sending deleted decisions to central API: %s", err)
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
			p.Logger.Errorf("sending deleted decisions to central API: %s", err)
		}
		pageStart += bulkSize
		pageEnd += bulkSize
	}
}
