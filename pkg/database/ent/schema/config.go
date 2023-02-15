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

// Fields of the Bouncer.
func (ConfigItem) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).Nillable().Optional().StructTag(`json:"created_at"`),
		field.Time("updated_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).Nillable().Optional().StructTag(`json:"updated_at"`),
		field.String("name").Unique().StructTag(`json:"name"`),
		field.String("value").StructTag(`json:"value"`), // a json object
	}
}

// Edges of the Bouncer.
func (ConfigItem) Edges() []ent.Edge {
	return nil
}
