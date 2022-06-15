// Code generated by entc, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
)

// Machine is the model entity for the Machine schema.
type Machine struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt *time.Time `json:"created_at,omitempty"`
	// UpdatedAt holds the value of the "updated_at" field.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// LastPush holds the value of the "last_push" field.
	LastPush *time.Time `json:"last_push,omitempty"`
	// LastHeartbeat holds the value of the "last_heartbeat" field.
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
	// MachineId holds the value of the "machineId" field.
	MachineId string `json:"machineId,omitempty"`
	// Password holds the value of the "password" field.
	Password string `json:"-"`
	// IpAddress holds the value of the "ipAddress" field.
	IpAddress string `json:"ipAddress,omitempty"`
	// Scenarios holds the value of the "scenarios" field.
	Scenarios string `json:"scenarios,omitempty"`
	// Version holds the value of the "version" field.
	Version string `json:"version,omitempty"`
	// IsValidated holds the value of the "isValidated" field.
	IsValidated bool `json:"isValidated,omitempty"`
	// Status holds the value of the "status" field.
	Status string `json:"status,omitempty"`
	// AuthType holds the value of the "auth_type" field.
	AuthType string `json:"auth_type"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the MachineQuery when eager-loading is set.
	Edges MachineEdges `json:"edges"`
}

// MachineEdges holds the relations/edges for other nodes in the graph.
type MachineEdges struct {
	// Alerts holds the value of the alerts edge.
	Alerts []*Alert `json:"alerts,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// AlertsOrErr returns the Alerts value or an error if the edge
// was not loaded in eager-loading.
func (e MachineEdges) AlertsOrErr() ([]*Alert, error) {
	if e.loadedTypes[0] {
		return e.Alerts, nil
	}
	return nil, &NotLoadedError{edge: "alerts"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Machine) scanValues(columns []string) ([]interface{}, error) {
	values := make([]interface{}, len(columns))
	for i := range columns {
		switch columns[i] {
		case machine.FieldIsValidated:
			values[i] = new(sql.NullBool)
		case machine.FieldID:
			values[i] = new(sql.NullInt64)
		case machine.FieldMachineId, machine.FieldPassword, machine.FieldIpAddress, machine.FieldScenarios, machine.FieldVersion, machine.FieldStatus, machine.FieldAuthType:
			values[i] = new(sql.NullString)
		case machine.FieldCreatedAt, machine.FieldUpdatedAt, machine.FieldLastPush, machine.FieldLastHeartbeat:
			values[i] = new(sql.NullTime)
		default:
			return nil, fmt.Errorf("unexpected column %q for type Machine", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Machine fields.
func (m *Machine) assignValues(columns []string, values []interface{}) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case machine.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			m.ID = int(value.Int64)
		case machine.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				m.CreatedAt = new(time.Time)
				*m.CreatedAt = value.Time
			}
		case machine.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				m.UpdatedAt = new(time.Time)
				*m.UpdatedAt = value.Time
			}
		case machine.FieldLastPush:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field last_push", values[i])
			} else if value.Valid {
				m.LastPush = new(time.Time)
				*m.LastPush = value.Time
			}
		case machine.FieldLastHeartbeat:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field last_heartbeat", values[i])
			} else if value.Valid {
				m.LastHeartbeat = new(time.Time)
				*m.LastHeartbeat = value.Time
			}
		case machine.FieldMachineId:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field machineId", values[i])
			} else if value.Valid {
				m.MachineId = value.String
			}
		case machine.FieldPassword:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field password", values[i])
			} else if value.Valid {
				m.Password = value.String
			}
		case machine.FieldIpAddress:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field ipAddress", values[i])
			} else if value.Valid {
				m.IpAddress = value.String
			}
		case machine.FieldScenarios:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field scenarios", values[i])
			} else if value.Valid {
				m.Scenarios = value.String
			}
		case machine.FieldVersion:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field version", values[i])
			} else if value.Valid {
				m.Version = value.String
			}
		case machine.FieldIsValidated:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field isValidated", values[i])
			} else if value.Valid {
				m.IsValidated = value.Bool
			}
		case machine.FieldStatus:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field status", values[i])
			} else if value.Valid {
				m.Status = value.String
			}
		case machine.FieldAuthType:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field auth_type", values[i])
			} else if value.Valid {
				m.AuthType = value.String
			}
		}
	}
	return nil
}

// QueryAlerts queries the "alerts" edge of the Machine entity.
func (m *Machine) QueryAlerts() *AlertQuery {
	return (&MachineClient{config: m.config}).QueryAlerts(m)
}

// Update returns a builder for updating this Machine.
// Note that you need to call Machine.Unwrap() before calling this method if this Machine
// was returned from a transaction, and the transaction was committed or rolled back.
func (m *Machine) Update() *MachineUpdateOne {
	return (&MachineClient{config: m.config}).UpdateOne(m)
}

// Unwrap unwraps the Machine entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (m *Machine) Unwrap() *Machine {
	tx, ok := m.config.driver.(*txDriver)
	if !ok {
		panic("ent: Machine is not a transactional entity")
	}
	m.config.driver = tx.drv
	return m
}

// String implements the fmt.Stringer.
func (m *Machine) String() string {
	var builder strings.Builder
	builder.WriteString("Machine(")
	builder.WriteString(fmt.Sprintf("id=%v", m.ID))
	if v := m.CreatedAt; v != nil {
		builder.WriteString(", created_at=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	if v := m.UpdatedAt; v != nil {
		builder.WriteString(", updated_at=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	if v := m.LastPush; v != nil {
		builder.WriteString(", last_push=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	if v := m.LastHeartbeat; v != nil {
		builder.WriteString(", last_heartbeat=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", machineId=")
	builder.WriteString(m.MachineId)
	builder.WriteString(", password=<sensitive>")
	builder.WriteString(", ipAddress=")
	builder.WriteString(m.IpAddress)
	builder.WriteString(", scenarios=")
	builder.WriteString(m.Scenarios)
	builder.WriteString(", version=")
	builder.WriteString(m.Version)
	builder.WriteString(", isValidated=")
	builder.WriteString(fmt.Sprintf("%v", m.IsValidated))
	builder.WriteString(", status=")
	builder.WriteString(m.Status)
	builder.WriteString(", auth_type=")
	builder.WriteString(m.AuthType)
	builder.WriteByte(')')
	return builder.String()
}

// Machines is a parsable slice of Machine.
type Machines []*Machine

func (m Machines) config(cfg config) {
	for _i := range m {
		m[_i].config = cfg
	}
}
