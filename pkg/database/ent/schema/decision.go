package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// Decision holds the schema definition for the Decision entity.
type Decision struct {
	ent.Schema
}

// Fields of the Decision.
func (Decision) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).Nillable().Optional(),
		field.Time("updated_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).Nillable().Optional(),
		field.Time("until"),
		field.String("scenario"),
		field.String("type"),
		field.Int64("start_ip").Optional(),
		field.Int64("end_ip").Optional(),
		field.Int64("start_suffix").Optional(),
		field.Int64("end_suffix").Optional(),
		field.Int64("ip_size").Optional(),
		field.String("scope"),
		field.String("value"),
		field.String("origin"),
		field.Bool("simulated").Default(false),
	}
}

// Edges of the Decision.
func (Decision) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", Alert.Type).
			Ref("decisions").
			Unique(),
	}
}
