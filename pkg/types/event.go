package types

import (
	"net"
	"time"
)

const (
	LOG = iota
	OVFLW
)

type Event struct {
	/* is it a log or an overflow */
	Type            int    `yaml:"Type,omitempty"`
	ExpectMode      int    `yaml:"ExpectMode,omitempty"` //how to buckets should handle event : leaky.TIMEMACHINE or leaky.LIVE
	Whitelisted     bool   `yaml:"Whitelisted,omitempty"`
	WhiteListReason string `json:"whitelist_reason,omitempty"`
	//should add whitelist reason ?
	/* the current stage of the line being parsed */
	Stage string `yaml:"Stage,omitempty"`
	/* original line (produced by acquisition) */
	Line Line `json:"Line" yaml:"Line,omitempty"`
	/* output of groks */
	Parsed map[string]string `json:"Parsed,omitempty" yaml:"Parsed,omitempty"`
	/* output of enrichment */
	Enriched map[string]string `json:"Enriched,omitempty" yaml:"Enriched,omitempty"`
	/* Overflow */
	Overflow      Alert     `yaml:"Alert,omitempty"`
	Time          time.Time `json:"Time,omitempty"` //parsed time `json:"-"` ``
	StrTime       string    `yaml:"StrTime,omitempty"`
	MarshaledTime string    `yaml:"MarshaledTime,omitempty"`
	Process       bool      `yaml:"Process,omitempty"` //can be set to false to avoid processing line
	/* Meta is the only part that will make it to the API - it should be normalized */
	Meta map[string]string `json:"Meta,omitempty" yaml:"Meta,omitempty"`
}

type Decision struct {
	Origin string /*cscli,crowdsec,...*/
	Type   string /*ban,slow,captcha,whatever*/
	Scope  string /*ip,range,username,toto,lol*/
	Target string /*in case we need extra info for the connector ?*/
	/*only relevant if the scope is an IP or a range*/
	StartIP uint32
	EndIP   uint32

	Duration time.Duration /*expiration of ban*/

	Message  string /*long human reason of the ban 'ban AS1234' */
	Scenario string /*the type of scenario that led to ban*/
}

//EventSequence is used to represent the summarized version of events that lead to overflow
type EventSequence struct {
	Time time.Time
	//Serialized string            //the serialized dict evt.Meta
	Meta map[string]string //the evt.Meta
}

//Source is the generic representation of a source ip implicated in events / overflows. It contains both information extracted directly from logs and enrichment
type Source struct {
	Scope string `yaml:"scope"`
	Value string `yaml:"value"`

	Ip                           net.IP    `yaml:"ipv4"` //shorthand for scope=ip&value=<X>
	Range                        net.IPNet `yaml:"range"`
	AutonomousSystemNumber       string
	AutonomousSystemOrganization string
	Country                      string
	Latitude                     float64
	Longitude                    float64
}

type Alert struct {
	/*bucket mgmt*/
	Mapkey    string //related to bucket mgmt, it's the partition identifier of a bucket
	Bucket_id string //The 'runtime' bucket-name (mostly for debug), ie. `sunny-flower`

	/*actual overflow*/
	Scenario    string    `yaml:"scenario"` //The unique name of the scenario, ie. ssh_bruteforce_multi-user
	Message     string    //Human-friendly label (to be displayed)
	EventsCount int       `yaml:"events_count"` //Number of events between first occurence and ban
	StartAt     time.Time //first event (usually bucket creation time)
	StopAt      time.Time //last event (usually bucket overflow time)
	Capacity    int
	LeakSpeed   time.Duration
	Whitelisted bool
	Simulated   bool
	//Reprocess, when true, will make the overflow being processed again as a fresh log would
	Reprocess bool
	/*Events that constituted the actual overflow*/
	Events []EventSequence //When adapted, a unique list of string representing the individual events that lead to the overflow
	/*Associated decisions*/
	Decisions []Decision
	/*all the source implicated in said overflow*/
	Sources map[string]Source `yaml:"sources"`
	/*defined by user/bucket configuration*/
	Labels map[string]string
}
