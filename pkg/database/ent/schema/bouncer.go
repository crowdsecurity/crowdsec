package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// Bouncer holds the schema definition for the Bouncer entity.
type Bouncer struct {
	ent.Schema
}

// Fields of the Bouncer.
func (Bouncer) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).Nillable().Optional(),
		field.Time("updated_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).Nillable().Optional(),
		field.String("name").Unique(),
		field.String("api_key"), // hash of api_key
		field.Bool("revoked"),
		field.String("ip_address").Default("").Optional(),
		field.String("type").Optional(),
		field.String("version").Optional(),
		field.Time("until").Default(types.UtcNow).Optional(),
		field.Time("last_pull").
			Default(types.UtcNow),
	}
}

// Edges of the Bouncer.
func (Bouncer) Edges() []ent.Edge {
	return nil
}
