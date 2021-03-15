package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect"

	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Event holds the schema definition for the Event entity.
type Event struct {
	ent.Schema
}

// Fields of the Event.
func (Event) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(time.Now),
		field.Time("updated_at").
			Default(time.Now),
		field.Time("time"),
		field.String("serialized").MaxLen(4095).SchemaType(map[string]string{
			dialect.MySQL:    "text",   // Override MySQL.
			dialect.Postgres: "text",   // Override Postgres.
			dialect.SQLite: "text",   // Override SQLite
		}),
	}
}

// Edges of the Event.
func (Event) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", Alert.Type).
			Ref("events").
			Unique(),
	}
}
