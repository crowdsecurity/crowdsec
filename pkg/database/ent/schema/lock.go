package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type Lock struct {
	ent.Schema
}

func (Lock) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").Unique().StructTag(`json:"name"`),
		field.Time("created_at").Default(types.UtcNow).StructTag(`json:"created_at"`),
	}
}

func (Lock) Edges() []ent.Edge {
	return nil
}
