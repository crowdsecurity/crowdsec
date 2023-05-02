// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/configitem"
)

// ConfigItem is the model entity for the ConfigItem schema.
type ConfigItem struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt *time.Time `json:"created_at"`
	// UpdatedAt holds the value of the "updated_at" field.
	UpdatedAt *time.Time `json:"updated_at"`
	// Name holds the value of the "name" field.
	Name string `json:"name"`
	// Value holds the value of the "value" field.
	Value string `json:"value"`
}

// scanValues returns the types for scanning values from sql.Rows.
func (*ConfigItem) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case configitem.FieldID:
			values[i] = new(sql.NullInt64)
		case configitem.FieldName, configitem.FieldValue:
			values[i] = new(sql.NullString)
		case configitem.FieldCreatedAt, configitem.FieldUpdatedAt:
			values[i] = new(sql.NullTime)
		default:
			return nil, fmt.Errorf("unexpected column %q for type ConfigItem", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the ConfigItem fields.
func (ci *ConfigItem) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case configitem.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			ci.ID = int(value.Int64)
		case configitem.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				ci.CreatedAt = new(time.Time)
				*ci.CreatedAt = value.Time
			}
		case configitem.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				ci.UpdatedAt = new(time.Time)
				*ci.UpdatedAt = value.Time
			}
		case configitem.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				ci.Name = value.String
			}
		case configitem.FieldValue:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field value", values[i])
			} else if value.Valid {
				ci.Value = value.String
			}
		}
	}
	return nil
}

// Update returns a builder for updating this ConfigItem.
// Note that you need to call ConfigItem.Unwrap() before calling this method if this ConfigItem
// was returned from a transaction, and the transaction was committed or rolled back.
func (ci *ConfigItem) Update() *ConfigItemUpdateOne {
	return (&ConfigItemClient{config: ci.config}).UpdateOne(ci)
}

// Unwrap unwraps the ConfigItem entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (ci *ConfigItem) Unwrap() *ConfigItem {
	_tx, ok := ci.config.driver.(*txDriver)
	if !ok {
		panic("ent: ConfigItem is not a transactional entity")
	}
	ci.config.driver = _tx.drv
	return ci
}

// String implements the fmt.Stringer.
func (ci *ConfigItem) String() string {
	var builder strings.Builder
	builder.WriteString("ConfigItem(")
	builder.WriteString(fmt.Sprintf("id=%v, ", ci.ID))
	if v := ci.CreatedAt; v != nil {
		builder.WriteString("created_at=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", ")
	if v := ci.UpdatedAt; v != nil {
		builder.WriteString("updated_at=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", ")
	builder.WriteString("name=")
	builder.WriteString(ci.Name)
	builder.WriteString(", ")
	builder.WriteString("value=")
	builder.WriteString(ci.Value)
	builder.WriteByte(')')
	return builder.String()
}

// ConfigItems is a parsable slice of ConfigItem.
type ConfigItems []*ConfigItem

func (ci ConfigItems) config(cfg config) {
	for _i := range ci {
		ci[_i].config = cfg
	}
}
