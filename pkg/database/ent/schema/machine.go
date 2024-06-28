package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// Machine holds the schema definition for the Machine entity.
type Machine struct {
	ent.Schema
}

// Fields of the Machine.
func (Machine) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(types.UtcNow).
			Immutable(),
		field.Time("updated_at").
			Default(types.UtcNow).
			UpdateDefault(types.UtcNow),
		field.Time("last_push").
			Default(types.UtcNow).
			Nillable().Optional(),
		field.Time("last_heartbeat").
			Nillable().Optional(),
		field.String("machineId").
			Unique().
			Immutable(),
		field.String("password").Sensitive(),
		field.String("ipAddress"),
		field.String("scenarios").MaxLen(100000).Optional(),
		field.String("version").Optional(),
		field.Bool("isValidated").
			Default(false),
		field.String("status").Optional(),
		field.String("auth_type").Default(types.PasswordAuthType).StructTag(`json:"auth_type"`),
		field.String("osname").Optional(),
		field.String("osversion").Optional(),
		field.String("featureflags").Optional(),
		field.JSON("hubstate", &models.HubItems{}).Optional(),
		field.JSON("datasources", map[string]int64{}).Optional(),
	}
}

//type HubItemState struct {
//	Version string `json:"version"`
//	Status string `json:"status"`
//}
//
//type HubState struct {
//	// the key is the FQName (type:author/name)
//	Items map[string]HubItemState `json:"hub_items"`
//}

// Edges of the Machine.
func (Machine) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("alerts", Alert.Type),
	}
}
