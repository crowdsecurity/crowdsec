package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
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
		field.Time("received_at").
			Immutable().
			Comment("When the metrics are received by LAPI"),
		field.Time("pushed_at").
			Nillable().
			Optional().
			Comment("When the metrics are sent to the console"),
		field.Text("payload").
			Immutable().
			Comment("The actual metrics (item0)"),
	}
}
