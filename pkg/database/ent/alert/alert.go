// Code generated by entc, DO NOT EDIT.

package alert

import (
	"time"
)

const (
	// Label holds the string label denoting the alert type in the database.
	Label = "alert"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldCreatedAt holds the string denoting the created_at field in the database.
	FieldCreatedAt = "created_at"
	// FieldUpdatedAt holds the string denoting the updated_at field in the database.
	FieldUpdatedAt = "updated_at"
	// FieldScenario holds the string denoting the scenario field in the database.
	FieldScenario = "scenario"
	// FieldBucketId holds the string denoting the bucketid field in the database.
	FieldBucketId = "bucket_id"
	// FieldMessage holds the string denoting the message field in the database.
	FieldMessage = "message"
	// FieldEventsCount holds the string denoting the eventscount field in the database.
	FieldEventsCount = "events_count"
	// FieldStartedAt holds the string denoting the startedat field in the database.
	FieldStartedAt = "started_at"
	// FieldStoppedAt holds the string denoting the stoppedat field in the database.
	FieldStoppedAt = "stopped_at"
	// FieldSourceIp holds the string denoting the sourceip field in the database.
	FieldSourceIp = "source_ip"
	// FieldSourceRange holds the string denoting the sourcerange field in the database.
	FieldSourceRange = "source_range"
	// FieldSourceAsNumber holds the string denoting the sourceasnumber field in the database.
	FieldSourceAsNumber = "source_as_number"
	// FieldSourceAsName holds the string denoting the sourceasname field in the database.
	FieldSourceAsName = "source_as_name"
	// FieldSourceCountry holds the string denoting the sourcecountry field in the database.
	FieldSourceCountry = "source_country"
	// FieldSourceLatitude holds the string denoting the sourcelatitude field in the database.
	FieldSourceLatitude = "source_latitude"
	// FieldSourceLongitude holds the string denoting the sourcelongitude field in the database.
	FieldSourceLongitude = "source_longitude"
	// FieldSourceScope holds the string denoting the sourcescope field in the database.
	FieldSourceScope = "source_scope"
	// FieldSourceValue holds the string denoting the sourcevalue field in the database.
	FieldSourceValue = "source_value"
	// FieldCapacity holds the string denoting the capacity field in the database.
	FieldCapacity = "capacity"
	// FieldLeakSpeed holds the string denoting the leakspeed field in the database.
	FieldLeakSpeed = "leak_speed"
	// FieldScenarioVersion holds the string denoting the scenarioversion field in the database.
	FieldScenarioVersion = "scenario_version"
	// FieldScenarioHash holds the string denoting the scenariohash field in the database.
	FieldScenarioHash = "scenario_hash"
	// FieldSimulated holds the string denoting the simulated field in the database.
	FieldSimulated = "simulated"
	// EdgeOwner holds the string denoting the owner edge name in mutations.
	EdgeOwner = "owner"
	// EdgeDecisions holds the string denoting the decisions edge name in mutations.
	EdgeDecisions = "decisions"
	// EdgeEvents holds the string denoting the events edge name in mutations.
	EdgeEvents = "events"
	// EdgeMetas holds the string denoting the metas edge name in mutations.
	EdgeMetas = "metas"
	// Table holds the table name of the alert in the database.
	Table = "alerts"
	// OwnerTable is the table the holds the owner relation/edge.
	OwnerTable = "alerts"
	// OwnerInverseTable is the table name for the Machine entity.
	// It exists in this package in order to avoid circular dependency with the "machine" package.
	OwnerInverseTable = "machines"
	// OwnerColumn is the table column denoting the owner relation/edge.
	OwnerColumn = "machine_alerts"
	// DecisionsTable is the table the holds the decisions relation/edge.
	DecisionsTable = "decisions"
	// DecisionsInverseTable is the table name for the Decision entity.
	// It exists in this package in order to avoid circular dependency with the "decision" package.
	DecisionsInverseTable = "decisions"
	// DecisionsColumn is the table column denoting the decisions relation/edge.
	DecisionsColumn = "alert_decisions"
	// EventsTable is the table the holds the events relation/edge.
	EventsTable = "events"
	// EventsInverseTable is the table name for the Event entity.
	// It exists in this package in order to avoid circular dependency with the "event" package.
	EventsInverseTable = "events"
	// EventsColumn is the table column denoting the events relation/edge.
	EventsColumn = "alert_events"
	// MetasTable is the table the holds the metas relation/edge.
	MetasTable = "meta"
	// MetasInverseTable is the table name for the Meta entity.
	// It exists in this package in order to avoid circular dependency with the "meta" package.
	MetasInverseTable = "meta"
	// MetasColumn is the table column denoting the metas relation/edge.
	MetasColumn = "alert_metas"
)

// Columns holds all SQL columns for alert fields.
var Columns = []string{
	FieldID,
	FieldCreatedAt,
	FieldUpdatedAt,
	FieldScenario,
	FieldBucketId,
	FieldMessage,
	FieldEventsCount,
	FieldStartedAt,
	FieldStoppedAt,
	FieldSourceIp,
	FieldSourceRange,
	FieldSourceAsNumber,
	FieldSourceAsName,
	FieldSourceCountry,
	FieldSourceLatitude,
	FieldSourceLongitude,
	FieldSourceScope,
	FieldSourceValue,
	FieldCapacity,
	FieldLeakSpeed,
	FieldScenarioVersion,
	FieldScenarioHash,
	FieldSimulated,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "alerts"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"machine_alerts",
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	for i := range ForeignKeys {
		if column == ForeignKeys[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultCreatedAt holds the default value on creation for the "created_at" field.
	DefaultCreatedAt func() time.Time
	// DefaultUpdatedAt holds the default value on creation for the "updated_at" field.
	DefaultUpdatedAt func() time.Time
	// DefaultBucketId holds the default value on creation for the "bucketId" field.
	DefaultBucketId string
	// DefaultMessage holds the default value on creation for the "message" field.
	DefaultMessage string
	// DefaultEventsCount holds the default value on creation for the "eventsCount" field.
	DefaultEventsCount int32
	// DefaultStartedAt holds the default value on creation for the "startedAt" field.
	DefaultStartedAt func() time.Time
	// DefaultStoppedAt holds the default value on creation for the "stoppedAt" field.
	DefaultStoppedAt func() time.Time
	// DefaultSimulated holds the default value on creation for the "simulated" field.
	DefaultSimulated bool
)
