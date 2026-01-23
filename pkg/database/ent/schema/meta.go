package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Meta holds the schema definition for the Meta entity.
type Meta struct {
	ent.Schema
}

// Fields of the Meta.
func (Meta) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(UtcNow).Immutable(),
		field.Time("updated_at").
			Default(UtcNow).
			UpdateDefault(UtcNow),
		field.String("key").Immutable(),
		field.String("value").MaxLen(4095).Immutable(),
		field.Int("alert_metas").Optional(),
	}
}

// Edges of the Meta.
func (Meta) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", Alert.Type).
			Ref("metas").
			Field("alert_metas").
			Unique(),
	}
}

func (Meta) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("alert_metas"),
	}
}
