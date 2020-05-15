package types

import (
	"time"

	"github.com/jinzhu/gorm"
)

type SignalOccurence struct {
	gorm.Model `json:"-"`
	//	ID              uint            //  `json:"-" gorm:"primary_key,AUTO_INCREMENT"`
	MapKey          string           //for Delete
	Scenario        string           `json:"scenario,omitempty"`                                              //The unique name of the scenario, ie. ssh_bruteforce_multi-user
	Bucket_id       string           `json:"bucket_id,omitempty"`                                             //The 'runtime' bucket-name (mostly for debug), ie. `sunny-flower`
	Alert_message   string           `json:"alert_message,omitempty"`                                         //Human-friendly label (to be displayed)
	Events_count    int              `json:"events_count,omitempty" yaml:"Events_count,omitempty"`            //Number of events between first occurence and ban
	Events_sequence []EventSequence  `json:"-" gorm:"foreignkey:SignalOccurenceID;association_foreignkey:ID"` //When adapted, a unique list of string representing the individual events that lead to the overflow
	Start_at        time.Time        `json:"start_at,omitempty"`                                              //first event (usually bucket creation time)
	BanApplications []BanApplication `json:"ban_applications,omitempty" gorm:"foreignkey:SignalOccurenceID;association_foreignkey:ID"`
	Stop_at         time.Time        `json:"stop_at,omitempty"` //last event (usually bucket overflow time)
	Source          *Source          `json:"source"`            //`json:"source,omitempty"`
	/*for db*/
	Source_ip                           string `yaml:"Source_ip,omitempty"`
	Source_range                        string
	Source_AutonomousSystemNumber       string
	Source_AutonomousSystemOrganization string
	Source_Country                      string
	Source_Latitude                     float64
	Source_Longitude                    float64
	/*/for db*/
	Sources map[string]Source `json:"sources,omitempty" gorm:"-"`
	// Source_ip       string          `json:"src_ip,omitempty"`                                                                        //for now just the IP
	// Source_as       string          `json:"src_as,omitempty"`                                                                        //for now just the as (AS number)
	// Source_country  string          `json:"src_country,omitempty"`                                                                   //for now just the county (two-letter iso-code)
	Dest_ip string `json:"dst_ip,omitempty"` //for now just the destination IP
	//Policy  string `json:"policy,omitempty"` //for now we forward it as well :)
	//bucket info
	Capacity   int           `json:"capacity,omitempty"`
	Leak_speed time.Duration `json:"leak_speed,omitempty"`

	Reprocess bool              //Reprocess, when true, will make the overflow being processed again as a fresh log would
	Labels    map[string]string `gorm:"-"`
}
