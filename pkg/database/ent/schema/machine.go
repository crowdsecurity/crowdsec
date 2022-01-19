package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// Machine holds the schema definition for the Machine entity.
type Machine struct {
	ent.Schema
}

// Fields of the Machine.
func (Machine) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).Nillable().Optional(),
		field.Time("updated_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).Nillable().Optional(),
		field.Time("last_push").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).Nillable().Optional(),
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
