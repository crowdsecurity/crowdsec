package apiserver

import (
	"encoding/json"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/jcuga/golongpoll/client"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	PAPI_PULL_KEY = "papi:last_pull"
)

func PapiError(err error) bool {
	log.Warningf("PAPI/ERROR : %s", err)
	return true
}

//PullPAPI is the long polling client for real-time decisions from PAPI
func (a *apic) PullPAPI() error {

	defer types.CatchPanic("lapi/PullPAPI")
	log.Infof("Starting Polling API Pull")

	if a.apiClient.PapiURL == nil {
		return errors.New("PAPI URL is nil")
	}
	c, err := client.NewClient(client.ClientOptions{
		SubscribeUrl:   *a.apiClient.PapiURL,
		Category:       "some-category", //what should we do with this one ?
		HttpClient:     a.apiClient.GetClient(),
		OnFailure:      PapiError,
		LoggingEnabled: true,
	})
	if err != nil {
		return errors.Wrap(err, "failed to create PAPI client")
	}

	lastTimestamp := time.Now().UTC()
	lastTimestampStr, err := a.dbClient.GetConfigItem(PAPI_PULL_KEY)
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
		a.dbClient.SetConfigItem(PAPI_PULL_KEY, string(binTime))
	} else {
		if err := lastTimestamp.UnmarshalText([]byte(*lastTimestampStr)); err != nil {
			return errors.Wrap(err, "failed to unmarshal last timestamp")
		}
	}

	log.Infof("Starting PAPI pull (since:%s)", lastTimestamp)
	for event := range c.Start(lastTimestamp) {
		//update last timestamp in database
		newTime := time.Now().UTC()
		binTime, err := newTime.MarshalText()
		if err != nil {
			return errors.Wrap(err, "failed to marshal last timestamp")
		}
		if err := a.dbClient.SetConfigItem(PAPI_PULL_KEY, string(binTime)); err != nil {
			return errors.Wrap(err, "failed to update last timestamp")
		} else {
			log.Debugf("set last timestamp to %s", newTime)
		}

		//do the marshal dance
		bin, err := json.Marshal(event.Data)
		if err != nil {
			return errors.Wrap(err, "failed to marshal event data")
		}
		alert := models.Alert{}

		if err := json.Unmarshal(bin, &alert); err != nil {
			return errors.Wrap(err, "failed to unmarshal event data")
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
		_, err = a.dbClient.CreateOrUpdateAlert("", &alert)
		if err != nil {
			log.Errorf("Failed to create alerts in DB: %s", err)
		} else {
			a.AlertsAddChan <- []*models.Alert{&alert}
		}
	}
	return nil
}
