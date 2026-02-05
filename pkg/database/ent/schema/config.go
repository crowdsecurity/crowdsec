package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/field"
)

// ConfigItem holds the schema definition for the ConfigItem entity.
type ConfigItem struct {
	ent.Schema
}

func (ConfigItem) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(UtcNow).
			Immutable().
			StructTag(`json:"created_at"`),
		field.Time("updated_at").
			Default(UtcNow).
			UpdateDefault(UtcNow).StructTag(`json:"updated_at"`),
		field.String("name").Unique().StructTag(`json:"name"`).Immutable(),
		field.String("value").SchemaType(map[string]string{
			dialect.MySQL:    "longtext",
			dialect.Postgres: "text",
		}).StructTag(`json:"value"`), // a json object
	}
}

func (ConfigItem) Edges() []ent.Edge {
	return nil
}
