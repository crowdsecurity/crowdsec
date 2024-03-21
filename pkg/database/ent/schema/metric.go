package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Metric is actually a set of metrics collected by a device (logprocessor, bouncer, etc) at a given time.
type Metric struct {
	ent.Schema
}


// TODO:
// respect unique index on (generated_type, generated_by, collected_at)
// when we send, set pushed_at
// housekeeping: retention period wrt collected_at?
// do we blindly trust collected_at? refuse if too old? refuse if too much in the future?

// Fields of the Machine.
func (Metric) Fields() []ent.Field {
	return []ent.Field{
		// XXX: type tout court?
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
		// Can we have a json/jsonbb field? with two different schemas?
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
		// XXX: we happy with the generated index name?
}
