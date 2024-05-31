// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/bouncer"
)

// Bouncer is the model entity for the Bouncer schema.
type Bouncer struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt holds the value of the "updated_at" field.
	UpdatedAt time.Time `json:"updated_at"`
	// Name holds the value of the "name" field.
	Name string `json:"name"`
	// APIKey holds the value of the "api_key" field.
	APIKey string `json:"-"`
	// Revoked holds the value of the "revoked" field.
	Revoked bool `json:"revoked"`
	// IPAddress holds the value of the "ip_address" field.
	IPAddress string `json:"ip_address"`
	// Type holds the value of the "type" field.
	Type string `json:"type"`
	// Version holds the value of the "version" field.
	Version string `json:"version"`
	// LastPull holds the value of the "last_pull" field.
	LastPull *time.Time `json:"last_pull"`
	// AuthType holds the value of the "auth_type" field.
	AuthType     string `json:"auth_type"`
	selectValues sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Bouncer) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case bouncer.FieldRevoked:
			values[i] = new(sql.NullBool)
		case bouncer.FieldID:
			values[i] = new(sql.NullInt64)
		case bouncer.FieldName, bouncer.FieldAPIKey, bouncer.FieldIPAddress, bouncer.FieldType, bouncer.FieldVersion, bouncer.FieldAuthType:
			values[i] = new(sql.NullString)
		case bouncer.FieldCreatedAt, bouncer.FieldUpdatedAt, bouncer.FieldLastPull:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Bouncer fields.
func (b *Bouncer) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case bouncer.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			b.ID = int(value.Int64)
		case bouncer.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				b.CreatedAt = value.Time
			}
		case bouncer.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				b.UpdatedAt = value.Time
			}
		case bouncer.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				b.Name = value.String
			}
		case bouncer.FieldAPIKey:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field api_key", values[i])
			} else if value.Valid {
				b.APIKey = value.String
			}
		case bouncer.FieldRevoked:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field revoked", values[i])
			} else if value.Valid {
				b.Revoked = value.Bool
			}
		case bouncer.FieldIPAddress:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field ip_address", values[i])
			} else if value.Valid {
				b.IPAddress = value.String
			}
		case bouncer.FieldType:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field type", values[i])
			} else if value.Valid {
				b.Type = value.String
			}
		case bouncer.FieldVersion:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field version", values[i])
			} else if value.Valid {
				b.Version = value.String
			}
		case bouncer.FieldLastPull:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field last_pull", values[i])
			} else if value.Valid {
				b.LastPull = new(time.Time)
				*b.LastPull = value.Time
			}
		case bouncer.FieldAuthType:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field auth_type", values[i])
			} else if value.Valid {
				b.AuthType = value.String
			}
		default:
			b.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Bouncer.
// This includes values selected through modifiers, order, etc.
func (b *Bouncer) Value(name string) (ent.Value, error) {
	return b.selectValues.Get(name)
}

// Update returns a builder for updating this Bouncer.
// Note that you need to call Bouncer.Unwrap() before calling this method if this Bouncer
// was returned from a transaction, and the transaction was committed or rolled back.
func (b *Bouncer) Update() *BouncerUpdateOne {
	return NewBouncerClient(b.config).UpdateOne(b)
}

// Unwrap unwraps the Bouncer entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (b *Bouncer) Unwrap() *Bouncer {
	_tx, ok := b.config.driver.(*txDriver)
	if !ok {
		panic("ent: Bouncer is not a transactional entity")
	}
	b.config.driver = _tx.drv
	return b
}

// String implements the fmt.Stringer.
func (b *Bouncer) String() string {
	var builder strings.Builder
	builder.WriteString("Bouncer(")
	builder.WriteString(fmt.Sprintf("id=%v, ", b.ID))
	builder.WriteString("created_at=")
	builder.WriteString(b.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("updated_at=")
	builder.WriteString(b.UpdatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("name=")
	builder.WriteString(b.Name)
	builder.WriteString(", ")
	builder.WriteString("api_key=<sensitive>")
	builder.WriteString(", ")
	builder.WriteString("revoked=")
	builder.WriteString(fmt.Sprintf("%v", b.Revoked))
	builder.WriteString(", ")
	builder.WriteString("ip_address=")
	builder.WriteString(b.IPAddress)
	builder.WriteString(", ")
	builder.WriteString("type=")
	builder.WriteString(b.Type)
	builder.WriteString(", ")
	builder.WriteString("version=")
	builder.WriteString(b.Version)
	builder.WriteString(", ")
	if v := b.LastPull; v != nil {
		builder.WriteString("last_pull=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", ")
	builder.WriteString("auth_type=")
	builder.WriteString(b.AuthType)
	builder.WriteByte(')')
	return builder.String()
}

// Bouncers is a parsable slice of Bouncer.
type Bouncers []*Bouncer
