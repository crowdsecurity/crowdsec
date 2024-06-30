package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Metric is actually a set of metrics collected by a device
// (logprocessor, bouncer, etc) at a given time.
type Metric struct {
	ent.Schema
}

func (Metric) Fields() []ent.Field {
	return []ent.Field{
	        field.Enum("generated_type").
			Values("LP", "RC").
			Immutable().
			Comment("Type of the metrics source: LP=logprocessor, RC=remediation"),
		field.String("generated_by").
			Immutable().
			Comment("Source of the metrics: machine id, bouncer name...\nIt must come from the auth middleware."),
		field.Time("collected_at").
			Immutable().
			Comment("When the metrics are collected/calculated at the source"),
		field.Time("pushed_at").
			Nillable().
			Optional().
			Comment("When the metrics are sent to the console"),
		field.String("payload").
			Immutable().
			Comment("The actual metrics (item0)"),
	}
}

func (Metric) Indexes() []ent.Index {
	return []ent.Index{
		// Don't store the same metrics multiple times.
		index.Fields("generated_type", "generated_by", "collected_at").
			Unique(),
		}
}
