package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// ConfigItem holds the schema definition for the ConfigItem entity.
type ConfigItem struct {
	ent.Schema
}

func (ConfigItem) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(types.UtcNow).
			Immutable().
			StructTag(`json:"created_at"`),
		field.Time("updated_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).StructTag(`json:"updated_at"`),
		field.String("name").Unique().StructTag(`json:"name"`).Immutable(),
		field.String("value").StructTag(`json:"value"`), // a json object
	}
}

func (ConfigItem) Edges() []ent.Edge {
	return nil
}
