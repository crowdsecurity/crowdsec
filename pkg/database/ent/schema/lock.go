package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

type Lock struct {
	ent.Schema
}

func (Lock) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").Unique().Immutable().StructTag(`json:"name"`),
		field.Time("created_at").Default(UtcNow).StructTag(`json:"created_at"`).Immutable(),
	}
}

func (Lock) Edges() []ent.Edge {
	return nil
}
