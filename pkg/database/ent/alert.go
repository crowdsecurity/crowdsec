// Code generated by entc, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/facebook/ent/dialect/sql"
)

// Alert is the model entity for the Alert schema.
type Alert struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// UpdatedAt holds the value of the "updated_at" field.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// Scenario holds the value of the "scenario" field.
	Scenario string `json:"scenario,omitempty"`
	// BucketId holds the value of the "bucketId" field.
	BucketId string `json:"bucketId,omitempty"`
	// Message holds the value of the "message" field.
	Message string `json:"message,omitempty"`
	// EventsCount holds the value of the "eventsCount" field.
	EventsCount int32 `json:"eventsCount,omitempty"`
	// StartedAt holds the value of the "startedAt" field.
	StartedAt time.Time `json:"startedAt,omitempty"`
	// StoppedAt holds the value of the "stoppedAt" field.
	StoppedAt time.Time `json:"stoppedAt,omitempty"`
	// SourceIp holds the value of the "sourceIp" field.
	SourceIp string `json:"sourceIp,omitempty"`
	// SourceRange holds the value of the "sourceRange" field.
	SourceRange string `json:"sourceRange,omitempty"`
	// SourceAsNumber holds the value of the "sourceAsNumber" field.
	SourceAsNumber string `json:"sourceAsNumber,omitempty"`
	// SourceAsName holds the value of the "sourceAsName" field.
	SourceAsName string `json:"sourceAsName,omitempty"`
	// SourceCountry holds the value of the "sourceCountry" field.
	SourceCountry string `json:"sourceCountry,omitempty"`
	// SourceLatitude holds the value of the "sourceLatitude" field.
	SourceLatitude float32 `json:"sourceLatitude,omitempty"`
	// SourceLongitude holds the value of the "sourceLongitude" field.
	SourceLongitude float32 `json:"sourceLongitude,omitempty"`
	// SourceScope holds the value of the "sourceScope" field.
	SourceScope string `json:"sourceScope,omitempty"`
	// SourceValue holds the value of the "sourceValue" field.
	SourceValue string `json:"sourceValue,omitempty"`
	// Capacity holds the value of the "capacity" field.
	Capacity int32 `json:"capacity,omitempty"`
	// LeakSpeed holds the value of the "leakSpeed" field.
	LeakSpeed string `json:"leakSpeed,omitempty"`
	// ScenarioVersion holds the value of the "scenarioVersion" field.
	ScenarioVersion string `json:"scenarioVersion,omitempty"`
	// ScenarioHash holds the value of the "scenarioHash" field.
	ScenarioHash string `json:"scenarioHash,omitempty"`
	// Simulated holds the value of the "simulated" field.
	Simulated bool `json:"simulated,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the AlertQuery when eager-loading is set.
	Edges          AlertEdges `json:"edges"`
	machine_alerts *int
}

// AlertEdges holds the relations/edges for other nodes in the graph.
type AlertEdges struct {
	// Owner holds the value of the owner edge.
	Owner *Machine
	// Decisions holds the value of the decisions edge.
	Decisions []*Decision
	// Events holds the value of the events edge.
	Events []*Event
	// Metas holds the value of the metas edge.
	Metas []*Meta
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [4]bool
}

// OwnerOrErr returns the Owner value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e AlertEdges) OwnerOrErr() (*Machine, error) {
	if e.loadedTypes[0] {
		if e.Owner == nil {
			// The edge owner was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: machine.Label}
		}
		return e.Owner, nil
	}
	return nil, &NotLoadedError{edge: "owner"}
}

// DecisionsOrErr returns the Decisions value or an error if the edge
// was not loaded in eager-loading.
func (e AlertEdges) DecisionsOrErr() ([]*Decision, error) {
	if e.loadedTypes[1] {
		return e.Decisions, nil
	}
	return nil, &NotLoadedError{edge: "decisions"}
}

// EventsOrErr returns the Events value or an error if the edge
// was not loaded in eager-loading.
func (e AlertEdges) EventsOrErr() ([]*Event, error) {
	if e.loadedTypes[2] {
		return e.Events, nil
	}
	return nil, &NotLoadedError{edge: "events"}
}

// MetasOrErr returns the Metas value or an error if the edge
// was not loaded in eager-loading.
func (e AlertEdges) MetasOrErr() ([]*Meta, error) {
	if e.loadedTypes[3] {
		return e.Metas, nil
	}
	return nil, &NotLoadedError{edge: "metas"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Alert) scanValues() []interface{} {
	return []interface{}{
		&sql.NullInt64{},   // id
		&sql.NullTime{},    // created_at
		&sql.NullTime{},    // updated_at
		&sql.NullString{},  // scenario
		&sql.NullString{},  // bucketId
		&sql.NullString{},  // message
		&sql.NullInt64{},   // eventsCount
		&sql.NullTime{},    // startedAt
		&sql.NullTime{},    // stoppedAt
		&sql.NullString{},  // sourceIp
		&sql.NullString{},  // sourceRange
		&sql.NullString{},  // sourceAsNumber
		&sql.NullString{},  // sourceAsName
		&sql.NullString{},  // sourceCountry
		&sql.NullFloat64{}, // sourceLatitude
		&sql.NullFloat64{}, // sourceLongitude
		&sql.NullString{},  // sourceScope
		&sql.NullString{},  // sourceValue
		&sql.NullInt64{},   // capacity
		&sql.NullString{},  // leakSpeed
		&sql.NullString{},  // scenarioVersion
		&sql.NullString{},  // scenarioHash
		&sql.NullBool{},    // simulated
	}
}

// fkValues returns the types for scanning foreign-keys values from sql.Rows.
func (*Alert) fkValues() []interface{} {
	return []interface{}{
		&sql.NullInt64{}, // machine_alerts
	}
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Alert fields.
func (a *Alert) assignValues(values ...interface{}) error {
	if m, n := len(values), len(alert.Columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	value, ok := values[0].(*sql.NullInt64)
	if !ok {
		return fmt.Errorf("unexpected type %T for field id", value)
	}
	a.ID = int(value.Int64)
	values = values[1:]
	if value, ok := values[0].(*sql.NullTime); !ok {
		return fmt.Errorf("unexpected type %T for field created_at", values[0])
	} else if value.Valid {
		a.CreatedAt = value.Time
	}
	if value, ok := values[1].(*sql.NullTime); !ok {
		return fmt.Errorf("unexpected type %T for field updated_at", values[1])
	} else if value.Valid {
		a.UpdatedAt = value.Time
	}
	if value, ok := values[2].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field scenario", values[2])
	} else if value.Valid {
		a.Scenario = value.String
	}
	if value, ok := values[3].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field bucketId", values[3])
	} else if value.Valid {
		a.BucketId = value.String
	}
	if value, ok := values[4].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field message", values[4])
	} else if value.Valid {
		a.Message = value.String
	}
	if value, ok := values[5].(*sql.NullInt64); !ok {
		return fmt.Errorf("unexpected type %T for field eventsCount", values[5])
	} else if value.Valid {
		a.EventsCount = int32(value.Int64)
	}
	if value, ok := values[6].(*sql.NullTime); !ok {
		return fmt.Errorf("unexpected type %T for field startedAt", values[6])
	} else if value.Valid {
		a.StartedAt = value.Time
	}
	if value, ok := values[7].(*sql.NullTime); !ok {
		return fmt.Errorf("unexpected type %T for field stoppedAt", values[7])
	} else if value.Valid {
		a.StoppedAt = value.Time
	}
	if value, ok := values[8].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field sourceIp", values[8])
	} else if value.Valid {
		a.SourceIp = value.String
	}
	if value, ok := values[9].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field sourceRange", values[9])
	} else if value.Valid {
		a.SourceRange = value.String
	}
	if value, ok := values[10].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field sourceAsNumber", values[10])
	} else if value.Valid {
		a.SourceAsNumber = value.String
	}
	if value, ok := values[11].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field sourceAsName", values[11])
	} else if value.Valid {
		a.SourceAsName = value.String
	}
	if value, ok := values[12].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field sourceCountry", values[12])
	} else if value.Valid {
		a.SourceCountry = value.String
	}
	if value, ok := values[13].(*sql.NullFloat64); !ok {
		return fmt.Errorf("unexpected type %T for field sourceLatitude", values[13])
	} else if value.Valid {
		a.SourceLatitude = float32(value.Float64)
	}
	if value, ok := values[14].(*sql.NullFloat64); !ok {
		return fmt.Errorf("unexpected type %T for field sourceLongitude", values[14])
	} else if value.Valid {
		a.SourceLongitude = float32(value.Float64)
	}
	if value, ok := values[15].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field sourceScope", values[15])
	} else if value.Valid {
		a.SourceScope = value.String
	}
	if value, ok := values[16].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field sourceValue", values[16])
	} else if value.Valid {
		a.SourceValue = value.String
	}
	if value, ok := values[17].(*sql.NullInt64); !ok {
		return fmt.Errorf("unexpected type %T for field capacity", values[17])
	} else if value.Valid {
		a.Capacity = int32(value.Int64)
	}
	if value, ok := values[18].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field leakSpeed", values[18])
	} else if value.Valid {
		a.LeakSpeed = value.String
	}
	if value, ok := values[19].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field scenarioVersion", values[19])
	} else if value.Valid {
		a.ScenarioVersion = value.String
	}
	if value, ok := values[20].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field scenarioHash", values[20])
	} else if value.Valid {
		a.ScenarioHash = value.String
	}
	if value, ok := values[21].(*sql.NullBool); !ok {
		return fmt.Errorf("unexpected type %T for field simulated", values[21])
	} else if value.Valid {
		a.Simulated = value.Bool
	}
	values = values[22:]
	if len(values) == len(alert.ForeignKeys) {
		if value, ok := values[0].(*sql.NullInt64); !ok {
			return fmt.Errorf("unexpected type %T for edge-field machine_alerts", value)
		} else if value.Valid {
			a.machine_alerts = new(int)
			*a.machine_alerts = int(value.Int64)
		}
	}
	return nil
}

// QueryOwner queries the owner edge of the Alert.
func (a *Alert) QueryOwner() *MachineQuery {
	return (&AlertClient{config: a.config}).QueryOwner(a)
}

// QueryDecisions queries the decisions edge of the Alert.
func (a *Alert) QueryDecisions() *DecisionQuery {
	return (&AlertClient{config: a.config}).QueryDecisions(a)
}

// QueryEvents queries the events edge of the Alert.
func (a *Alert) QueryEvents() *EventQuery {
	return (&AlertClient{config: a.config}).QueryEvents(a)
}

// QueryMetas queries the metas edge of the Alert.
func (a *Alert) QueryMetas() *MetaQuery {
	return (&AlertClient{config: a.config}).QueryMetas(a)
}

// Update returns a builder for updating this Alert.
// Note that, you need to call Alert.Unwrap() before calling this method, if this Alert
// was returned from a transaction, and the transaction was committed or rolled back.
func (a *Alert) Update() *AlertUpdateOne {
	return (&AlertClient{config: a.config}).UpdateOne(a)
}

// Unwrap unwraps the entity that was returned from a transaction after it was closed,
// so that all next queries will be executed through the driver which created the transaction.
func (a *Alert) Unwrap() *Alert {
	tx, ok := a.config.driver.(*txDriver)
	if !ok {
		panic("ent: Alert is not a transactional entity")
	}
	a.config.driver = tx.drv
	return a
}

// String implements the fmt.Stringer.
func (a *Alert) String() string {
	var builder strings.Builder
	builder.WriteString("Alert(")
	builder.WriteString(fmt.Sprintf("id=%v", a.ID))
	builder.WriteString(", created_at=")
	builder.WriteString(a.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", updated_at=")
	builder.WriteString(a.UpdatedAt.Format(time.ANSIC))
	builder.WriteString(", scenario=")
	builder.WriteString(a.Scenario)
	builder.WriteString(", bucketId=")
	builder.WriteString(a.BucketId)
	builder.WriteString(", message=")
	builder.WriteString(a.Message)
	builder.WriteString(", eventsCount=")
	builder.WriteString(fmt.Sprintf("%v", a.EventsCount))
	builder.WriteString(", startedAt=")
	builder.WriteString(a.StartedAt.Format(time.ANSIC))
	builder.WriteString(", stoppedAt=")
	builder.WriteString(a.StoppedAt.Format(time.ANSIC))
	builder.WriteString(", sourceIp=")
	builder.WriteString(a.SourceIp)
	builder.WriteString(", sourceRange=")
	builder.WriteString(a.SourceRange)
	builder.WriteString(", sourceAsNumber=")
	builder.WriteString(a.SourceAsNumber)
	builder.WriteString(", sourceAsName=")
	builder.WriteString(a.SourceAsName)
	builder.WriteString(", sourceCountry=")
	builder.WriteString(a.SourceCountry)
	builder.WriteString(", sourceLatitude=")
	builder.WriteString(fmt.Sprintf("%v", a.SourceLatitude))
	builder.WriteString(", sourceLongitude=")
	builder.WriteString(fmt.Sprintf("%v", a.SourceLongitude))
	builder.WriteString(", sourceScope=")
	builder.WriteString(a.SourceScope)
	builder.WriteString(", sourceValue=")
	builder.WriteString(a.SourceValue)
	builder.WriteString(", capacity=")
	builder.WriteString(fmt.Sprintf("%v", a.Capacity))
	builder.WriteString(", leakSpeed=")
	builder.WriteString(a.LeakSpeed)
	builder.WriteString(", scenarioVersion=")
	builder.WriteString(a.ScenarioVersion)
	builder.WriteString(", scenarioHash=")
	builder.WriteString(a.ScenarioHash)
	builder.WriteString(", simulated=")
	builder.WriteString(fmt.Sprintf("%v", a.Simulated))
	builder.WriteByte(')')
	return builder.String()
}

// Alerts is a parsable slice of Alert.
type Alerts []*Alert

func (a Alerts) config(cfg config) {
	for _i := range a {
		a[_i].config = cfg
	}
}
