package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// Alert holds the schema definition for the Alert entity.
type AllowList struct {
	ent.Schema
}

// Fields of the Alert.
func (AllowList) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(types.UtcNow).
			Immutable(),
		field.Time("updated_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow),
		field.String("name"),
		field.Bool("from_console"),
		field.String("description").Optional(),
		field.String("allowlist_id").Optional().Immutable(),
	}
}

func (AllowList) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("id").Unique(),
		index.Fields("name").Unique(),
	}
}

func (AllowList) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("allowlist_items", AllowListItem.Type),
	}
}
