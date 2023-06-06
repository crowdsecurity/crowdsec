package cticlient

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/go-cs-lib/pkg/ptr"
)

//func (c *SmokeItem) GetAttackDetails() []string {

func getSampleSmokeItem() SmokeItem {
	lat := 48.8566
	long := 2.3522
	emptyItem := SmokeItem{
		IpRangeScore: 2.0,
		Ip:           "1.2.3.4",
		IpRange:      ptr.Of("1.2.3.0/24"),
		AsName:       ptr.Of("AS1234"),
		AsNum:        ptr.Of(1234),
		Location: CTILocationInfo{
			Country:   ptr.Of("FR"),
			City:      ptr.Of("Paris"),
			Latitude:  &lat,
			Longitude: &long,
		},
		ReverseDNS: ptr.Of("foo.bar.com"),
		Behaviors: []*CTIBehavior{
			{
				Name:        "ssh:bruteforce",
				Label:       "SSH Bruteforce",
				Description: "IP has been reported for performing brute force on ssh services.",
			},
		},
		History: CTIHistory{
			FirstSeen: ptr.Of("2022-12-05T17:45:00+00:00"),
			LastSeen:  ptr.Of("2022-12-06T19:15:00+00:00"),
			FullAge:   3,
			DaysAge:   1,
		},
		Classifications: CTIClassifications{
			FalsePositives:  []CTIClassification{},
			Classifications: []CTIClassification{},
		},
		AttackDetails: []*CTIAttackDetails{
			{
				Name:        "ssh:bruteforce",
				Label:       "SSH Bruteforce",
				Description: "Detect ssh brute force",
				References:  []string{},
			},
		},
		TargetCountries: map[string]int{
			"HK": 71,
			"GB": 14,
			"US": 14,
		},
		BackgroundNoiseScore: ptr.Of(3),
		Scores: CTIScores{
			Overall: CTIScore{
				Aggressiveness: 2,
				Threat:         1,
				Trust:          1,
				Anomaly:        0,
				Total:          1,
			},
			LastDay: CTIScore{
				Aggressiveness: 2,
				Threat:         1,
				Trust:          1,
				Anomaly:        0,
				Total:          1,
			},
			LastWeek: CTIScore{
				Aggressiveness: 2,
				Threat:         1,
				Trust:          1,
				Anomaly:        0,
				Total:          1,
			},
			LastMonth: CTIScore{
				Aggressiveness: 2,
				Threat:         1,
				Trust:          1,
				Anomaly:        0,
				Total:          1,
			},
		},
	}
	return emptyItem
}

func TestBasicSmokeItem(t *testing.T) {
	item := getSampleSmokeItem()
	assert.Equal(t, item.GetAttackDetails(), []string{"ssh:bruteforce"})
	assert.Equal(t, item.GetBehaviors(), []string{"ssh:bruteforce"})
	assert.Equal(t, item.GetMaliciousnessScore(), float32(0.1))
	assert.Equal(t, item.IsPartOfCommunityBlocklist(), false)
	assert.Equal(t, item.GetBackgroundNoiseScore(), int(3))
	assert.Equal(t, item.GetFalsePositives(), []string{})
	assert.Equal(t, item.IsFalsePositive(), false)
}

func TestEmptySmokeItem(t *testing.T) {
	item := SmokeItem{}
	assert.Equal(t, item.GetAttackDetails(), []string{})
	assert.Equal(t, item.GetBehaviors(), []string{})
	assert.Equal(t, item.GetMaliciousnessScore(), float32(0.0))
	assert.Equal(t, item.IsPartOfCommunityBlocklist(), false)
	assert.Equal(t, item.GetBackgroundNoiseScore(), int(0))
	assert.Equal(t, item.GetFalsePositives(), []string{})
	assert.Equal(t, item.IsFalsePositive(), false)
}
