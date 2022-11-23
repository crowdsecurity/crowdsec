package cticlient

import "time"

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

type SmokeItem struct {
	IpRangeScore         int                 `json:"ip_range_score"`
	Ip                   string              `json:"ip"`
	IpRange              *string             `json:"ip_range"`
	AsName               *string             `json:"as_name"`
	AsNum                *int                `json:"as_num"`
	Location             CTILocationInfo     `json:"location"`
	ReverseDNS           *string             `json:"reverse_dns"`
	Behaviours           []*CTIBehaviour     `json:"behaviors"`
	History              CTIHistory          `json:"history"`
	Classifications      CTIClassifications  `json:"classifications"`
	AttackDetails        []*CTIAttackDetails `json:"attack_details"`
	TargetCountries      map[string]int      `json:"target_countries"`
	BackgroundNoiseScore *int                `json:"background_noise_score"`
	Scores               CTIScores           `json:"scores"`
	References           []string            `json:"references"`
	IsOk                 bool                `json:"-"`
}

type SearchIPResponse struct {
	Total    int         `json:"total"`
	NotFound int         `json:"not_found"`
	Items    []SmokeItem `json:"items"`
}

type FireItem struct {
	IpRangeScore         int                 `json:"ip_range_score"`
	Ip                   string              `json:"ip"`
	IpRange              *string             `json:"ip_range"`
	AsName               *string             `json:"as_name"`
	AsNum                *int                `json:"as_num"`
	Location             CTILocationInfo     `json:"location"`
	ReverseDNS           *string             `json:"reverse_dns"`
	Behaviours           []*CTIBehaviour     `json:"behaviors"`
	History              CTIHistory          `json:"history"`
	Classifications      CTIClassifications  `json:"classifications"`
	AttackDetails        []*CTIAttackDetails `json:"attack_details"`
	TargetCountries      map[string]int      `json:"target_countries"`
	BackgroundNoiseScore *int                `json:"background_noise_score"`
	Scores               CTIScores           `json:"scores"`
	References           []string            `json:"references"`
	Status               string              `json:"status"`
	Expiration           time.Time           `json:"expiration"`
}

type FireParams struct {
	Since *string `json:"since"`
	Page  *int    `json:"page"`
}

type FireResponse struct {
	Links struct {
		Self  string `json:"self"`
		Prev  string `json:"prev"`
		Next  string `json:"next"`
		First string `json:"first"`
	} `json:"_links"`
	Items []FireItem `json:"items"`
}

func (c *SmokeItem) GetAttackDetails() []string {
	var ret []string

	if c.AttackDetails != nil {
		for _, b := range c.AttackDetails {
			ret = append(ret, b.Name)
		}
	}
	return ret
}

func (c *SmokeItem) GetBehaviours() []string {
	var ret []string

	if c.Behaviours != nil {
		for _, b := range c.Behaviours {
			ret = append(ret, b.Name)
		}
	}
	return ret
}

// Provide the likelyhood of the IP being bad
func (c *SmokeItem) GetMaliciousnessScore() float32 {
	if c.IsPartOfCommunityBlocklist() {
		return 1.0
	}
	if c.Scores.LastDay.Total > 0 {
		return float32(c.Scores.LastDay.Total) / 10.0
	}
	return 0.0
}

func (c *SmokeItem) IsPartOfCommunityBlocklist() bool {
	if c.Classifications.Classifications != nil {
		for _, v := range c.Classifications.Classifications {
			if v.Name == "community-blocklist" {
				return true
			}
		}
	}

	return false
}

func (c *SmokeItem) GetBackgroundNoiseScore() int {
	if c.BackgroundNoiseScore != nil {
		return *c.BackgroundNoiseScore
	}
	return 0
}

func (c *SmokeItem) GetFalsePositives() []string {
	var ret []string

	if c.Classifications.FalsePositives != nil {
		for _, b := range c.Classifications.FalsePositives {
			ret = append(ret, b.Name)
		}
	}
	return ret
}

func (c *SmokeItem) IsFalsePositive() bool {

	if c.Classifications.FalsePositives != nil {
		if len(c.Classifications.FalsePositives) > 0 {
			return true
		}
	}

	return false
}

func (c *FireItem) GetAttackDetails() []string {
	var ret []string

	if c.AttackDetails != nil {
		for _, b := range c.AttackDetails {
			ret = append(ret, b.Name)
		}
	}
	return ret
}

func (c *FireItem) GetBehaviours() []string {
	var ret []string

	if c.Behaviours != nil {
		for _, b := range c.Behaviours {
			ret = append(ret, b.Name)
		}
	}
	return ret
}

// Provide the likelyhood of the IP being bad
func (c *FireItem) GetMaliciousnessScore() float32 {
	if c.IsPartOfCommunityBlocklist() {
		return 1.0
	}
	if c.Scores.LastDay.Total > 0 {
		return float32(c.Scores.LastDay.Total) / 10.0
	}
	return 0.0
}

func (c *FireItem) IsPartOfCommunityBlocklist() bool {
	if c.Classifications.Classifications != nil {
		for _, v := range c.Classifications.Classifications {
			if v.Name == "community-blocklist" {
				return true
			}
		}
	}

	return false
}

func (c *FireItem) GetBackgroundNoiseScore() int {
	if c.BackgroundNoiseScore != nil {
		return *c.BackgroundNoiseScore
	}
	return 0
}

func (c *FireItem) GetFalsePositives() []string {
	var ret []string

	if c.Classifications.FalsePositives != nil {
		for _, b := range c.Classifications.FalsePositives {
			ret = append(ret, b.Name)
		}
	}
	return ret
}

func (c *FireItem) IsFalsePositive() bool {

	if c.Classifications.FalsePositives != nil {
		if len(c.Classifications.FalsePositives) > 0 {
			return true
		}
	}

	return false
}
