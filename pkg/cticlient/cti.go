package cticlient

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/bluele/gcache"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

var CTIUrl = "https://cti.api.crowdsec.net/v2/smoke/"
var CTIApiKey = ""

func InitCTI(Key string, TTL time.Duration, Size int) {
	CTIApiKey = Key
	CTIInitCache(Size, TTL)
}

// This will skip a lot of map[string]interface{} and make it easier to use
type CTIResponse struct {
	IpRangeScore         *int                `json:"ip_range_score"`
	Ip                   *string             `json:"ip"`
	IpRange              *string             `json:"ip_range"`
	AsName               *string             `json:"as_name"`
	AsNum                *int                `json:"as_num"`
	Location             *CTILocationInfo    `json:"location"`
	ReverseDNS           *string             `json:"reverse_dns"`
	Behaviours           []*CTIBehaviour     `json:"behaviours"`
	History              *CTIHistory         `json:"history"`
	Classifications      *CTIClassifications `json:"classification"`
	AttackDetails        []*CTIAttackDetails `json:"attack_details"`
	TargetCountries      *map[string]int     `json:"target_countries"`
	BackgroundNoiseScore *int                `json:"background_noise_score"`
	Scores               *CTIScores          `json:"scores"`
}

type CTIScores struct {
	Overall   CTIScore `json:"overall"`
	LastDay   CTIScore `json:"last_day"`
	LastWeek  CTIScore `json:"last_week"`
	LastMonth CTIScore `json:"last_month"`
}

type CTIScore struct {
	Aggressiveness int `json:"aggressiveness"`
	Threat         int `json:"threat"`
	Trust          int `json:"trust"`
	Anomaly        int `json:"anomaly"`
	Total          int `json:"total"`
}

type CTIAttackDetails struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	References  []string `json:"references"`
}

type CTIClassifications struct {
	FalsePositives  []CTIClassification `json:"false_positives"`
	Classifications []CTIClassification `json:"classifications"`
}

type CTIClassification struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
}
type CTIHistory struct {
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	FullAge   int    `json:"full_age"`
	DaysAge   int    `json:"days_age"`
}

type CTIBehaviour struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
}
type CTILocationInfo struct {
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

func (c CTIResponse) GetBehaviours() []string {
	var ret []string

	if c.Behaviours != nil {
		for _, b := range c.Behaviours {
			ret = append(ret, b.Name)
		}
	}
	return ret
}

// placeholder for now, but provide helpers to the user to make his life easier
func (c CTIResponse) IsMalicious() bool {
	return true
}

func (c CTIResponse) IsPartOfCommunityBlocklist() bool {
	if c.Classifications != nil {
		if c.Classifications.Classifications != nil {
			for _, v := range c.Classifications.Classifications {
				if v.Name == "community-blocklist" {
					return true
				}
			}
		}
	}
	return false
}

func (c CTIResponse) GetBackgroundNoiseScore() int {
	if c.BackgroundNoiseScore != nil {
		return *c.BackgroundNoiseScore
	}
	return 0
}

func (c CTIResponse) IsFalsePositive() bool {
	if c.Classifications != nil {
		if c.Classifications.FalsePositives != nil {
			if len(c.Classifications.FalsePositives) > 0 {
				return true
			}
		}
	}
	return false
}

// Cache for responses
var CTICache gcache.Cache
var CacheExpiration time.Duration

func CTIInitCache(size int, ttl time.Duration) {
	CTICache = gcache.New(size).LRU().Build()
	CacheExpiration = ttl
}

func IpCTI(ip string) CTIResponse {
	var ctiResponse CTIResponse

	if CTIApiKey == "" {
		log.Warningf("IpCTI : no key provided, skipping")
		return ctiResponse
	}

	//already had result in cache
	if val, err := CTICache.Get(ip); err == nil {
		log.Debugf("IpCTI : cache hit for %s", ip)
		return val.(CTIResponse)
	}

	client := &http.Client{}
	req, _ := http.NewRequest("GET", CTIUrl+ip, nil)
	req.Header.Set("x-api-key", CTIApiKey)
	res, err := client.Do(req)
	if err != nil {
		log.Errorf("CTI query error : %s", err)
		return ctiResponse
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Errorf("error reading CTI resp : %s", err)
		return ctiResponse
	}

	if err := json.Unmarshal(body, &ctiResponse); err != nil {
		log.Warningf("While querying CTI for %s : %s", ip, err)
	}
	//store result in cache
	if err := CTICache.SetWithExpire(ip, ctiResponse, CacheExpiration); err != nil {
		log.Errorf("CTI : error while caching : %s", err)
	}

	log.Printf("-> %+v", spew.Sdump(ctiResponse))
	return ctiResponse
}
