package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// Event holds the schema definition for the Event entity.
type Event struct {
	ent.Schema
}

// Fields of the Event.
func (Event) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).Nillable().Optional(),
		field.Time("updated_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).Nillable().Optional(),
		field.Time("time"),
		field.String("serialized").MaxLen(8191),
		field.Int("alert_events").Optional(),
	}
}

// Edges of the Event.
func (Event) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", Alert.Type).
			Ref("events").
			Field("alert_events").
			Unique(),
	}
}

func (Event) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("alert_events"),
	}
}
