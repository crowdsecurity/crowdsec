package types

import (
	"time"

	"github.com/jinzhu/gorm"
)

//EventSequence is used to represent the summarized version of events that lead to overflow
type EventSequence struct {
	gorm.Model `json:"-"`
	Time       time.Time
	Source     Source `json:"-"`
	/*for db only :/ */
	Source_ip                           string
	Source_range                        string
	Source_AutonomousSystemNumber       string
	Source_AutonomousSystemOrganization string
	Source_Country                      string
	/*stop db only */
	SignalOccurenceID uint   //unique ID for the hasMany relation
	Serialized        string //the serialized dict
}
