package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Machine holds the schema definition for the Machine entity.
type Machine struct {
	ent.Schema
}

// Fields of the Machine.
func (Machine) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(time.Now),
		field.Time("updated_at").
			Default(time.Now),
		field.Time("last_push").
			Default(time.Now),
		field.String("machineId").Unique(),
		field.String("password").Sensitive(),
		field.String("ipAddress"),
		field.String("scenarios").MaxLen(4095).Optional(),
		field.String("version").Optional(),
		field.Bool("isValidated").
			Default(false),
		field.String("status").Optional(),
	}
}

// Edges of the Machine.
func (Machine) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("alerts", Alert.Type),
	}
}
