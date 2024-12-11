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
			StructTag(`json:"created_at"`).
			Immutable(),
		field.Time("updated_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow).StructTag(`json:"updated_at"`),
		field.String("name").Unique().StructTag(`json:"name"`).Immutable(),
		field.String("api_key").Sensitive(), // hash of api_key
		field.Bool("revoked").StructTag(`json:"revoked"`),
		field.String("ip_address").Default("").Optional().StructTag(`json:"ip_address"`),
		field.String("type").Optional().StructTag(`json:"type"`),
		field.String("version").Optional().StructTag(`json:"version"`),
		field.Time("last_pull").Nillable().Optional().StructTag(`json:"last_pull"`),
		field.String("auth_type").StructTag(`json:"auth_type"`).Default(types.ApiKeyAuthType),
		field.String("osname").Optional(),
		field.String("osversion").Optional(),
		field.String("featureflags").Optional(),
		// Old auto-created TLS bouncers will have a wrong value for this field
		field.Bool("auto_created").StructTag(`json:"auto_created"`).Default(false).Immutable(),
	}
}

// Edges of the Bouncer.
func (Bouncer) Edges() []ent.Edge {
	return nil
}
