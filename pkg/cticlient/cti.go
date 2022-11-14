package cticlient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/bluele/gcache"
	log "github.com/sirupsen/logrus"
)

var CTIUrl = "https://cti.api.dev.crowdsec.net"
var CTIUrlSuffix = "/v2/smoke/"
var CTIApiKey = ""

// this is set for non-recoverable errors, such as 403 when querying API or empty API key
var CTIApiEnabled = true

// when hitting quotas or auth errors, we temporarily disable the API
var CTIBackOffUntil time.Time
var CTIBackOffDuration time.Duration = 5 * time.Minute

var (
	ErrorAuth  = errors.New("unexpected http code : 403 Forbidden")
	ErrorLimit = errors.New("limit exceeded")
)

func InitCTI(Key *string, TTL *time.Duration, Size *int) error {
	if Key != nil {
		CTIApiKey = *Key
	} else {
		CTIApiEnabled = false
		return fmt.Errorf("CTI API key not set, CTI will not be available")
	}
	if Size == nil {
		Size = new(int)
		*Size = 1000
	}
	if TTL == nil {
		TTL = new(time.Duration)
		*TTL = 5 * time.Minute
	}

	CTIInitCache(*Size, *TTL)
	log.Warningf("heree wee gooooo")
	return nil
}

func ShutdownCTI() {
	if CTICache != nil {
		CTICache.Purge()
	}
	CTIApiKey = ""
	CTIApiEnabled = true
}

// This will skip a lot of map[string]interface{} and make it easier to use
type CTIResponse struct {
	IpRangeScore         int                 `json:"ip_range_score"`
	Ip                   string              `json:"ip"`
	IpRange              *string             `json:"ip_range"`
	AsName               *string             `json:"as_name"`
	AsNum                *int                `json:"as_num"`
	Location             CTILocationInfo     `json:"location"`
	ReverseDNS           *string             `json:"reverse_dns"`
	Behaviours           []*CTIBehaviour     `json:"behaviours"`
	History              CTIHistory          `json:"history"`
	Classifications      CTIClassifications  `json:"classification"`
	AttackDetails        []*CTIAttackDetails `json:"attack_details"`
	TargetCountries      map[string]int      `json:"target_countries"`
	BackgroundNoiseScore *int                `json:"background_noise_score"`
	Scores               CTIScores           `json:"scores"`
	References           []string            `json:"references"`
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
	FirstSeen *string `json:"first_seen"`
	LastSeen  *string `json:"last_seen"`
	FullAge   int     `json:"full_age"`
	DaysAge   int     `json:"days_age"`
}

type CTIBehaviour struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
}
type CTILocationInfo struct {
	Country   *string  `json:"country"`
	City      *string  `json:"city"`
	Latitude  *float64 `json:"latitude"`
	Longitude *float64 `json:"longitude"`
}

func (c CTIResponse) GetAttackDetails() []string {
	var ret []string

	if c.AttackDetails != nil {
		for _, b := range c.AttackDetails {
			ret = append(ret, b.Name)
		}
	}
	return ret
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

// Provide the likelyhood of the IP being bad
func (c CTIResponse) GetMaliciousnessScore() float32 {
	if c.IsPartOfCommunityBlocklist() {
		return 1.0
	}
	if c.Scores.LastDay.Total > 0 {
		return float32(c.Scores.LastDay.Total) / 10.0
	}
	return 0.0
}

func (c CTIResponse) IsPartOfCommunityBlocklist() bool {
	if c.Classifications.Classifications != nil {
		for _, v := range c.Classifications.Classifications {
			if v.Name == "community-blocklist" {
				return true
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
	if c.Classifications.FalsePositives != nil {
		if len(c.Classifications.FalsePositives) > 0 {
			return true
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

func APIQuery(ip string) (*CTIResponse, error) {
	var ctiResponse CTIResponse

	if CTIApiKey == "" {
		CTIApiEnabled = false
		return nil, fmt.Errorf("no API key")
	}

	//already had result in cache
	if val, err := CTICache.Get(ip); err == nil && val != nil {
		log.Printf("data is in cache :)")
		//dirty cast, should be improved
		ret := val.(CTIResponse)
		return &ret, nil
	}

	//we're told to back off
	if !CTIBackOffUntil.IsZero() && time.Now().Before(CTIBackOffUntil) {
		log.Warningf("CTI API is in backoff mode, will try again in %s", time.Now().Sub(CTIBackOffUntil))
		return &ctiResponse, nil
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", CTIUrl+CTIUrlSuffix+ip, nil)
	if err != nil {
		return nil, fmt.Errorf("error while creating request : %w", err)
	}
	req.Header.Set("x-api-key", CTIApiKey)
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error while querying CTI : %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		//auth error
		if res.StatusCode == 403 {
			return nil, ErrorAuth
		}
		//limit exceeded
		if res.StatusCode == 429 {
			CTIBackOffUntil = time.Now().Add(CTIBackOffDuration)
			return nil, ErrorLimit

		}
		return nil, fmt.Errorf("unexpected http code : %s", res.Status)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading CTI resp : %w", err)
	}

	if err := json.Unmarshal(body, &ctiResponse); err != nil {
		return nil, err
	}
	//store result in cache
	if err := CTICache.SetWithExpire(ip, ctiResponse, CacheExpiration); err != nil {
		return &ctiResponse, fmt.Errorf("error while storing result in cache : %w", err)
	}

	//log.Printf("-> %+v", spew.Sdump(ctiResponse))
	return &ctiResponse, nil
}

func IpCTI(ip string) CTIResponse {
	var ctiResponse CTIResponse

	log.Warningf("lalalallaal")

	if CTIApiEnabled == false {
		log.Warningf("CTI API is disabled, please check your configuration")
		return ctiResponse
	}

	if CTIApiKey == "" {
		log.Warningf("IpCTI : no key provided, skipping")
		return ctiResponse
	}
	//not very  elegant
	val, err := APIQuery(ip)
	if err != nil {
		if err == ErrorAuth {
			CTIApiEnabled = false
			log.Errorf("Invalid API key provided, disabling CTI API")
		}
		log.Warningf("Error while querying CTI : %s", err)
	}
	log.Printf("-> %+v", val)
	if val != nil {
		return *val
	}
	return ctiResponse
}
