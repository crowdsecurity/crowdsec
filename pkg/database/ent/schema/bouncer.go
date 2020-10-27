package schema

import (
	"time"

	"github.com/facebook/ent"
	"github.com/facebook/ent/schema/field"
)

// Bouncer holds the schema definition for the Bouncer entity.
type Bouncer struct {
	ent.Schema
}

// Fields of the Bouncer.
func (Bouncer) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(time.Now),
		field.Time("updated_at").
			Default(time.Now),
		field.String("name").Unique(),
		field.String("api_key"), // hash of api_key
		field.Bool("revoked"),
		field.String("ip_address").Default("").Optional(),
		field.String("type").Optional(),
		field.String("version").Optional(),
		field.Time("until").Default(time.Now).Optional(),
		field.Time("last_pull").
			Default(time.Now),
	}
}

// Edges of the Bouncer.
func (Bouncer) Edges() []ent.Edge {
	return nil
}
