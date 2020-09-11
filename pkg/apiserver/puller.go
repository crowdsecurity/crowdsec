package apiserver

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database"
)

var configFile = "./api.yaml"
var username = "machine_test_apil"
var password = "password_test_apil"
var pullInterval = "60m"

type Puller struct {
	//client   *cwapi.ApiCtx
	interval time.Duration
	dbClient *database.Client
}

/*func NewPuller(dbClient *database.Client) (*Puller, error) {
	apiClient := &cwapi.ApiCtx{}
	if err := apiClient.LoadConfig(configFile); err != nil {
		return &Puller{}, err
	}


	if err := apiClient.Signin(); err != nil {
		return &Puller{}, err
	}

	interval, err := time.ParseDuration(pullInterval)
	if err != nil {
		return &Puller{}, err
	}
	return &Puller{
		client:   apiClient,
		interval: interval,
		dbClient: dbClient,
	}, nil
}

func (p *Puller) Pull() {
	ticker := time.NewTicker(p.interval)

	for {
		select {
		case <-ticker.C:
			log.Printf("Pull Time")
			pulledData, err := p.client.PullTop()
			if err != nil {
				log.Fatalf("unable to pull top: %s", err)
			} else {
				for _, alert := range pulledData {
					alertCreated, err := p.dbClient.Ent.Alert.
						Create().
						SetScenario(alert["scenario"]).
						SetSourceIp(alert["range_ip"]).
						SetSourceAsNumber(alert["as_num"]).
						SetSourceAsName(alert["as_org"]).
						SetSourceCountry(alert["country"]).
						Save(p.dbClient.CTX)
					if err != nil {
						log.Fatalf("unable to create alors from topX: %s", err)
					}

					duration, err := time.ParseDuration(alert["expiration"])
					if err != nil {
						log.Fatalf("unable to parse decision duration '%s': %s", alert["expiration"], err)
					}
					startIP, endIP, err := controllers.GetIpsFromIpRange(alert["range_ip"])
					if err != nil {
						log.Fatalf("failed querying alerts: Range %v is not valid", alert["range_ip"])
					}

					_, err = p.dbClient.Ent.Decision.Create().
						SetUntil(time.Now().Add(duration)).
						SetScenario(alert["scenario"]).
						SetType(alert["action"]).
						SetStartIP(startIP).
						SetEndIP(endIP).
						SetTarget(alert["range_ip"]).
						SetScope("ip").
						SetOwner(alertCreated).Save(p.dbClient.CTX)
					if err != nil {
						log.Fatalf("failed creating decision from top: %v", err)
					}
				}
				log.Printf("TOPX Pulled (%d entries) !", len(pulledData))

			}
		}
	}
}
*/
