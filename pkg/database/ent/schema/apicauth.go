package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// ApicAuth holds the schema definition for the ApicAuth entity.
type ApicAuth struct {
	ent.Schema
}

// Fields of the ApicAuth.
func (ApicAuth) Fields() []ent.Field {
	return []ent.Field{
		field.String("token").NotEmpty(),
		field.Time("expiration"),
		field.String("singleton").Immutable().Unique(),
	}
}

// Edges of the ApicAuth.
func (ApicAuth) Edges() []ent.Edge {
	return nil
}
