package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// Decision holds the schema definition for the Decision entity.
type Decision struct {
	ent.Schema
}

// Fields of the Decision.
func (Decision) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(types.UtcNow).
			Immutable(),
		field.Time("updated_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow),
		field.Time("until").SchemaType(map[string]string{
			dialect.MySQL: "datetime",
		}),
		field.String("scenario").Immutable(),
		field.String("type").Immutable(),
		field.Int64("start_ip").Optional().Immutable(),
		field.Int64("end_ip").Optional().Immutable(),
		field.Int64("start_suffix").Optional().Immutable(),
		field.Int64("end_suffix").Optional().Immutable(),
		field.Int64("ip_size").Optional().Immutable(),
		field.String("scope").Immutable(),
		field.String("value").Immutable(),
		field.String("origin").Immutable(),
		field.Bool("simulated").Default(false).Immutable(),
		field.String("uuid").Optional().Immutable(), // this uuid is mostly here to ensure that CAPI/PAPI has a unique id for each decision
		field.Int("alert_decisions").Optional(),
	}
}

// Edges of the Decision.
func (Decision) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", Alert.Type).
			Ref("decisions").
			Field("alert_decisions").
			Unique(),
	}
}

func (Decision) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("start_ip", "end_ip"),
		index.Fields("value"),
		index.Fields("until"),
		index.Fields("alert_decisions"),
	}
}
