package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// AllowListItem holds the schema definition for the AllowListItem entity.
type AllowListItem struct {
	ent.Schema
}

// Fields of the AllowListItem.
func (AllowListItem) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(types.UtcNow).
			Immutable(),
		field.Time("updated_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow),
		field.Time("expires_at").
			Optional(),
		field.String("comment").Optional().Immutable(),
		field.String("value").Immutable(), // For textual representation of the IP/range
		// Use the same fields as the decision table
		field.Int64("start_ip").Optional().Immutable(),
		field.Int64("end_ip").Optional().Immutable(),
		field.Int64("start_suffix").Optional().Immutable(),
		field.Int64("end_suffix").Optional().Immutable(),
		field.Int64("ip_size").Optional().Immutable(),
	}
}

func (AllowListItem) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("id"),
		index.Fields("start_ip", "end_ip"),
	}
}

func (AllowListItem) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("allowlist", AllowList.Type).
			Ref("allowlist_items"),
	}
}
