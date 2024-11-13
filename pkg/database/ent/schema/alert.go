package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// Alert holds the schema definition for the Alert entity.
type Alert struct {
	ent.Schema
}

// Fields of the Alert.
func (Alert) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(types.UtcNow).
			Immutable(),
		field.Time("updated_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow),
		field.String("scenario").Immutable(),
		field.String("bucketId").Default("").Optional().Immutable(),
		field.String("message").Default("").Optional().Immutable(),
		field.Int32("eventsCount").Default(0).Optional().Immutable(),
		field.Time("startedAt").Default(types.UtcNow).Optional().Immutable(),
		field.Time("stoppedAt").Default(types.UtcNow).Optional().Immutable(),
		field.String("sourceIp").
			Optional().Immutable(),
		field.String("sourceRange").
			Optional().Immutable(),
		field.String("sourceAsNumber").
			Optional().Immutable(),
		field.String("sourceAsName").
			Optional().Immutable(),
		field.String("sourceCountry").
			Optional().Immutable(),
		field.Float32("sourceLatitude").
			Optional().Immutable(),
		field.Float32("sourceLongitude").
			Optional().Immutable(),
		field.String("sourceScope").Optional().Immutable(),
		field.String("sourceValue").Optional().Immutable(),
		field.Int32("capacity").Optional().Immutable(),
		field.String("leakSpeed").Optional().Immutable(),
		field.String("scenarioVersion").Optional().Immutable(),
		field.String("scenarioHash").Optional().Immutable(),
		field.Bool("simulated").Default(false).Immutable(),
		field.String("uuid").Optional().Immutable(), // this uuid is mostly here to ensure that CAPI/PAPI has a unique id for each alert
		field.Bool("remediation").Optional().Immutable(),
	}
}

// Edges of the Alert.
func (Alert) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", Machine.Type).
			Ref("alerts").
			Unique(),
		edge.To("decisions", Decision.Type).
			Annotations(entsql.Annotation{
				OnDelete: entsql.Cascade,
			}),
		edge.To("events", Event.Type).
			Annotations(entsql.Annotation{
				OnDelete: entsql.Cascade,
			}),
		edge.To("metas", Meta.Type).
			Annotations(entsql.Annotation{
				OnDelete: entsql.Cascade,
			}),
	}
}

func (Alert) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("id"),
	}
}
