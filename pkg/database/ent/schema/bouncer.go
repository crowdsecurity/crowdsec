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
			UpdateDefault(types.UtcNow).Nillable().Optional().StructTag(`json:"created_at"`),
		field.Time("updated_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).Nillable().Optional().StructTag(`json:"updated_at"`),
		field.String("name").Unique().StructTag(`json:"name"`),
		field.String("api_key").StructTag(`json:"api_key"`), // hash of api_key
		field.Bool("revoked").StructTag(`json:"revoked"`),
		field.String("ip_address").Default("").Optional().StructTag(`json:"ip_address"`),
		field.String("type").Optional().StructTag(`json:"type"`),
		field.String("version").Optional().StructTag(`json:"version"`),
		field.Time("until").Default(types.UtcNow).Optional().StructTag(`json:"until"`),
		field.Time("last_pull").
			Default(types.UtcNow).StructTag(`json:"last_pull"`),
	}
}

// Edges of the Bouncer.
func (Bouncer) Edges() []ent.Edge {
	return nil
}
