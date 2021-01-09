// Code generated by entc, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
	"github.com/facebook/ent/dialect/sql"
	"github.com/facebook/ent/dialect/sql/sqlgraph"
	"github.com/facebook/ent/schema/field"
)

// DecisionUpdate is the builder for updating Decision entities.
type DecisionUpdate struct {
	config
	hooks    []Hook
	mutation *DecisionMutation
}

// Where adds a new predicate for the DecisionUpdate builder.
func (du *DecisionUpdate) Where(ps ...predicate.Decision) *DecisionUpdate {
	du.mutation.predicates = append(du.mutation.predicates, ps...)
	return du
}

// SetCreatedAt sets the "created_at" field.
func (du *DecisionUpdate) SetCreatedAt(t time.Time) *DecisionUpdate {
	du.mutation.SetCreatedAt(t)
	return du
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableCreatedAt(t *time.Time) *DecisionUpdate {
	if t != nil {
		du.SetCreatedAt(*t)
	}
	return du
}

// SetUpdatedAt sets the "updated_at" field.
func (du *DecisionUpdate) SetUpdatedAt(t time.Time) *DecisionUpdate {
	du.mutation.SetUpdatedAt(t)
	return du
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableUpdatedAt(t *time.Time) *DecisionUpdate {
	if t != nil {
		du.SetUpdatedAt(*t)
	}
	return du
}

// SetUntil sets the "until" field.
func (du *DecisionUpdate) SetUntil(t time.Time) *DecisionUpdate {
	du.mutation.SetUntil(t)
	return du
}

// SetScenario sets the "scenario" field.
func (du *DecisionUpdate) SetScenario(s string) *DecisionUpdate {
	du.mutation.SetScenario(s)
	return du
}

// SetType sets the "type" field.
func (du *DecisionUpdate) SetType(s string) *DecisionUpdate {
	du.mutation.SetType(s)
	return du
}

// SetStartIP sets the "start_ip" field.
func (du *DecisionUpdate) SetStartIP(i int64) *DecisionUpdate {
	du.mutation.ResetStartIP()
	du.mutation.SetStartIP(i)
	return du
}

// SetNillableStartIP sets the "start_ip" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableStartIP(i *int64) *DecisionUpdate {
	if i != nil {
		du.SetStartIP(*i)
	}
	return du
}

// AddStartIP adds i to the "start_ip" field.
func (du *DecisionUpdate) AddStartIP(i int64) *DecisionUpdate {
	du.mutation.AddStartIP(i)
	return du
}

// ClearStartIP clears the value of the "start_ip" field.
func (du *DecisionUpdate) ClearStartIP() *DecisionUpdate {
	du.mutation.ClearStartIP()
	return du
}

// SetEndIP sets the "end_ip" field.
func (du *DecisionUpdate) SetEndIP(i int64) *DecisionUpdate {
	du.mutation.ResetEndIP()
	du.mutation.SetEndIP(i)
	return du
}

// SetNillableEndIP sets the "end_ip" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableEndIP(i *int64) *DecisionUpdate {
	if i != nil {
		du.SetEndIP(*i)
	}
	return du
}

// AddEndIP adds i to the "end_ip" field.
func (du *DecisionUpdate) AddEndIP(i int64) *DecisionUpdate {
	du.mutation.AddEndIP(i)
	return du
}

// ClearEndIP clears the value of the "end_ip" field.
func (du *DecisionUpdate) ClearEndIP() *DecisionUpdate {
	du.mutation.ClearEndIP()
	return du
}

// SetRangeStart sets the "range_start" field.
func (du *DecisionUpdate) SetRangeStart(i int64) *DecisionUpdate {
	du.mutation.ResetRangeStart()
	du.mutation.SetRangeStart(i)
	return du
}

// SetNillableRangeStart sets the "range_start" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableRangeStart(i *int64) *DecisionUpdate {
	if i != nil {
		du.SetRangeStart(*i)
	}
	return du
}

// AddRangeStart adds i to the "range_start" field.
func (du *DecisionUpdate) AddRangeStart(i int64) *DecisionUpdate {
	du.mutation.AddRangeStart(i)
	return du
}

// ClearRangeStart clears the value of the "range_start" field.
func (du *DecisionUpdate) ClearRangeStart() *DecisionUpdate {
	du.mutation.ClearRangeStart()
	return du
}

// SetRangeEnd sets the "range_end" field.
func (du *DecisionUpdate) SetRangeEnd(i int64) *DecisionUpdate {
	du.mutation.ResetRangeEnd()
	du.mutation.SetRangeEnd(i)
	return du
}

// SetNillableRangeEnd sets the "range_end" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableRangeEnd(i *int64) *DecisionUpdate {
	if i != nil {
		du.SetRangeEnd(*i)
	}
	return du
}

// AddRangeEnd adds i to the "range_end" field.
func (du *DecisionUpdate) AddRangeEnd(i int64) *DecisionUpdate {
	du.mutation.AddRangeEnd(i)
	return du
}

// ClearRangeEnd clears the value of the "range_end" field.
func (du *DecisionUpdate) ClearRangeEnd() *DecisionUpdate {
	du.mutation.ClearRangeEnd()
	return du
}

// SetSuffixStart sets the "suffix_start" field.
func (du *DecisionUpdate) SetSuffixStart(i int64) *DecisionUpdate {
	du.mutation.ResetSuffixStart()
	du.mutation.SetSuffixStart(i)
	return du
}

// SetNillableSuffixStart sets the "suffix_start" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableSuffixStart(i *int64) *DecisionUpdate {
	if i != nil {
		du.SetSuffixStart(*i)
	}
	return du
}

// AddSuffixStart adds i to the "suffix_start" field.
func (du *DecisionUpdate) AddSuffixStart(i int64) *DecisionUpdate {
	du.mutation.AddSuffixStart(i)
	return du
}

// ClearSuffixStart clears the value of the "suffix_start" field.
func (du *DecisionUpdate) ClearSuffixStart() *DecisionUpdate {
	du.mutation.ClearSuffixStart()
	return du
}

// SetSuffixEnd sets the "suffix_end" field.
func (du *DecisionUpdate) SetSuffixEnd(i int64) *DecisionUpdate {
	du.mutation.ResetSuffixEnd()
	du.mutation.SetSuffixEnd(i)
	return du
}

// SetNillableSuffixEnd sets the "suffix_end" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableSuffixEnd(i *int64) *DecisionUpdate {
	if i != nil {
		du.SetSuffixEnd(*i)
	}
	return du
}

// AddSuffixEnd adds i to the "suffix_end" field.
func (du *DecisionUpdate) AddSuffixEnd(i int64) *DecisionUpdate {
	du.mutation.AddSuffixEnd(i)
	return du
}

// ClearSuffixEnd clears the value of the "suffix_end" field.
func (du *DecisionUpdate) ClearSuffixEnd() *DecisionUpdate {
	du.mutation.ClearSuffixEnd()
	return du
}

// SetScope sets the "scope" field.
func (du *DecisionUpdate) SetScope(s string) *DecisionUpdate {
	du.mutation.SetScope(s)
	return du
}

// SetValue sets the "value" field.
func (du *DecisionUpdate) SetValue(s string) *DecisionUpdate {
	du.mutation.SetValue(s)
	return du
}

// SetOrigin sets the "origin" field.
func (du *DecisionUpdate) SetOrigin(s string) *DecisionUpdate {
	du.mutation.SetOrigin(s)
	return du
}

// SetSimulated sets the "simulated" field.
func (du *DecisionUpdate) SetSimulated(b bool) *DecisionUpdate {
	du.mutation.SetSimulated(b)
	return du
}

// SetNillableSimulated sets the "simulated" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableSimulated(b *bool) *DecisionUpdate {
	if b != nil {
		du.SetSimulated(*b)
	}
	return du
}

// SetOwnerID sets the "owner" edge to the Alert entity by ID.
func (du *DecisionUpdate) SetOwnerID(id int) *DecisionUpdate {
	du.mutation.SetOwnerID(id)
	return du
}

// SetNillableOwnerID sets the "owner" edge to the Alert entity by ID if the given value is not nil.
func (du *DecisionUpdate) SetNillableOwnerID(id *int) *DecisionUpdate {
	if id != nil {
		du = du.SetOwnerID(*id)
	}
	return du
}

// SetOwner sets the "owner" edge to the Alert entity.
func (du *DecisionUpdate) SetOwner(a *Alert) *DecisionUpdate {
	return du.SetOwnerID(a.ID)
}

// Mutation returns the DecisionMutation object of the builder.
func (du *DecisionUpdate) Mutation() *DecisionMutation {
	return du.mutation
}

// ClearOwner clears the "owner" edge to the Alert entity.
func (du *DecisionUpdate) ClearOwner() *DecisionUpdate {
	du.mutation.ClearOwner()
	return du
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (du *DecisionUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(du.hooks) == 0 {
		affected, err = du.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*DecisionMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			du.mutation = mutation
			affected, err = du.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(du.hooks) - 1; i >= 0; i-- {
			mut = du.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, du.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (du *DecisionUpdate) SaveX(ctx context.Context) int {
	affected, err := du.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (du *DecisionUpdate) Exec(ctx context.Context) error {
	_, err := du.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (du *DecisionUpdate) ExecX(ctx context.Context) {
	if err := du.Exec(ctx); err != nil {
		panic(err)
	}
}

func (du *DecisionUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   decision.Table,
			Columns: decision.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: decision.FieldID,
			},
		},
	}
	if ps := du.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := du.mutation.CreatedAt(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: decision.FieldCreatedAt,
		})
	}
	if value, ok := du.mutation.UpdatedAt(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: decision.FieldUpdatedAt,
		})
	}
	if value, ok := du.mutation.Until(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: decision.FieldUntil,
		})
	}
	if value, ok := du.mutation.Scenario(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: decision.FieldScenario,
		})
	}
	if value, ok := du.mutation.GetType(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: decision.FieldType,
		})
	}
	if value, ok := du.mutation.StartIP(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldStartIP,
		})
	}
	if value, ok := du.mutation.AddedStartIP(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldStartIP,
		})
	}
	if du.mutation.StartIPCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Column: decision.FieldStartIP,
		})
	}
	if value, ok := du.mutation.EndIP(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldEndIP,
		})
	}
	if value, ok := du.mutation.AddedEndIP(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldEndIP,
		})
	}
	if du.mutation.EndIPCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Column: decision.FieldEndIP,
		})
	}
	if value, ok := du.mutation.RangeStart(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldRangeStart,
		})
	}
	if value, ok := du.mutation.AddedRangeStart(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldRangeStart,
		})
	}
	if du.mutation.RangeStartCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Column: decision.FieldRangeStart,
		})
	}
	if value, ok := du.mutation.RangeEnd(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldRangeEnd,
		})
	}
	if value, ok := du.mutation.AddedRangeEnd(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldRangeEnd,
		})
	}
	if du.mutation.RangeEndCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Column: decision.FieldRangeEnd,
		})
	}
	if value, ok := du.mutation.SuffixStart(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldSuffixStart,
		})
	}
	if value, ok := du.mutation.AddedSuffixStart(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldSuffixStart,
		})
	}
	if du.mutation.SuffixStartCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Column: decision.FieldSuffixStart,
		})
	}
	if value, ok := du.mutation.SuffixEnd(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldSuffixEnd,
		})
	}
	if value, ok := du.mutation.AddedSuffixEnd(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldSuffixEnd,
		})
	}
	if du.mutation.SuffixEndCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Column: decision.FieldSuffixEnd,
		})
	}
	if value, ok := du.mutation.Scope(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: decision.FieldScope,
		})
	}
	if value, ok := du.mutation.Value(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: decision.FieldValue,
		})
	}
	if value, ok := du.mutation.Origin(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: decision.FieldOrigin,
		})
	}
	if value, ok := du.mutation.Simulated(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeBool,
			Value:  value,
			Column: decision.FieldSimulated,
		})
	}
	if du.mutation.OwnerCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   decision.OwnerTable,
			Columns: []string{decision.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: alert.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := du.mutation.OwnerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   decision.OwnerTable,
			Columns: []string{decision.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: alert.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, du.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{decision.Label}
		} else if cerr, ok := isSQLConstraintError(err); ok {
			err = cerr
		}
		return 0, err
	}
	return n, nil
}

// DecisionUpdateOne is the builder for updating a single Decision entity.
type DecisionUpdateOne struct {
	config
	hooks    []Hook
	mutation *DecisionMutation
}

// SetCreatedAt sets the "created_at" field.
func (duo *DecisionUpdateOne) SetCreatedAt(t time.Time) *DecisionUpdateOne {
	duo.mutation.SetCreatedAt(t)
	return duo
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableCreatedAt(t *time.Time) *DecisionUpdateOne {
	if t != nil {
		duo.SetCreatedAt(*t)
	}
	return duo
}

// SetUpdatedAt sets the "updated_at" field.
func (duo *DecisionUpdateOne) SetUpdatedAt(t time.Time) *DecisionUpdateOne {
	duo.mutation.SetUpdatedAt(t)
	return duo
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableUpdatedAt(t *time.Time) *DecisionUpdateOne {
	if t != nil {
		duo.SetUpdatedAt(*t)
	}
	return duo
}

// SetUntil sets the "until" field.
func (duo *DecisionUpdateOne) SetUntil(t time.Time) *DecisionUpdateOne {
	duo.mutation.SetUntil(t)
	return duo
}

// SetScenario sets the "scenario" field.
func (duo *DecisionUpdateOne) SetScenario(s string) *DecisionUpdateOne {
	duo.mutation.SetScenario(s)
	return duo
}

// SetType sets the "type" field.
func (duo *DecisionUpdateOne) SetType(s string) *DecisionUpdateOne {
	duo.mutation.SetType(s)
	return duo
}

// SetStartIP sets the "start_ip" field.
func (duo *DecisionUpdateOne) SetStartIP(i int64) *DecisionUpdateOne {
	duo.mutation.ResetStartIP()
	duo.mutation.SetStartIP(i)
	return duo
}

// SetNillableStartIP sets the "start_ip" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableStartIP(i *int64) *DecisionUpdateOne {
	if i != nil {
		duo.SetStartIP(*i)
	}
	return duo
}

// AddStartIP adds i to the "start_ip" field.
func (duo *DecisionUpdateOne) AddStartIP(i int64) *DecisionUpdateOne {
	duo.mutation.AddStartIP(i)
	return duo
}

// ClearStartIP clears the value of the "start_ip" field.
func (duo *DecisionUpdateOne) ClearStartIP() *DecisionUpdateOne {
	duo.mutation.ClearStartIP()
	return duo
}

// SetEndIP sets the "end_ip" field.
func (duo *DecisionUpdateOne) SetEndIP(i int64) *DecisionUpdateOne {
	duo.mutation.ResetEndIP()
	duo.mutation.SetEndIP(i)
	return duo
}

// SetNillableEndIP sets the "end_ip" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableEndIP(i *int64) *DecisionUpdateOne {
	if i != nil {
		duo.SetEndIP(*i)
	}
	return duo
}

// AddEndIP adds i to the "end_ip" field.
func (duo *DecisionUpdateOne) AddEndIP(i int64) *DecisionUpdateOne {
	duo.mutation.AddEndIP(i)
	return duo
}

// ClearEndIP clears the value of the "end_ip" field.
func (duo *DecisionUpdateOne) ClearEndIP() *DecisionUpdateOne {
	duo.mutation.ClearEndIP()
	return duo
}

// SetRangeStart sets the "range_start" field.
func (duo *DecisionUpdateOne) SetRangeStart(i int64) *DecisionUpdateOne {
	duo.mutation.ResetRangeStart()
	duo.mutation.SetRangeStart(i)
	return duo
}

// SetNillableRangeStart sets the "range_start" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableRangeStart(i *int64) *DecisionUpdateOne {
	if i != nil {
		duo.SetRangeStart(*i)
	}
	return duo
}

// AddRangeStart adds i to the "range_start" field.
func (duo *DecisionUpdateOne) AddRangeStart(i int64) *DecisionUpdateOne {
	duo.mutation.AddRangeStart(i)
	return duo
}

// ClearRangeStart clears the value of the "range_start" field.
func (duo *DecisionUpdateOne) ClearRangeStart() *DecisionUpdateOne {
	duo.mutation.ClearRangeStart()
	return duo
}

// SetRangeEnd sets the "range_end" field.
func (duo *DecisionUpdateOne) SetRangeEnd(i int64) *DecisionUpdateOne {
	duo.mutation.ResetRangeEnd()
	duo.mutation.SetRangeEnd(i)
	return duo
}

// SetNillableRangeEnd sets the "range_end" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableRangeEnd(i *int64) *DecisionUpdateOne {
	if i != nil {
		duo.SetRangeEnd(*i)
	}
	return duo
}

// AddRangeEnd adds i to the "range_end" field.
func (duo *DecisionUpdateOne) AddRangeEnd(i int64) *DecisionUpdateOne {
	duo.mutation.AddRangeEnd(i)
	return duo
}

// ClearRangeEnd clears the value of the "range_end" field.
func (duo *DecisionUpdateOne) ClearRangeEnd() *DecisionUpdateOne {
	duo.mutation.ClearRangeEnd()
	return duo
}

// SetSuffixStart sets the "suffix_start" field.
func (duo *DecisionUpdateOne) SetSuffixStart(i int64) *DecisionUpdateOne {
	duo.mutation.ResetSuffixStart()
	duo.mutation.SetSuffixStart(i)
	return duo
}

// SetNillableSuffixStart sets the "suffix_start" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableSuffixStart(i *int64) *DecisionUpdateOne {
	if i != nil {
		duo.SetSuffixStart(*i)
	}
	return duo
}

// AddSuffixStart adds i to the "suffix_start" field.
func (duo *DecisionUpdateOne) AddSuffixStart(i int64) *DecisionUpdateOne {
	duo.mutation.AddSuffixStart(i)
	return duo
}

// ClearSuffixStart clears the value of the "suffix_start" field.
func (duo *DecisionUpdateOne) ClearSuffixStart() *DecisionUpdateOne {
	duo.mutation.ClearSuffixStart()
	return duo
}

// SetSuffixEnd sets the "suffix_end" field.
func (duo *DecisionUpdateOne) SetSuffixEnd(i int64) *DecisionUpdateOne {
	duo.mutation.ResetSuffixEnd()
	duo.mutation.SetSuffixEnd(i)
	return duo
}

// SetNillableSuffixEnd sets the "suffix_end" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableSuffixEnd(i *int64) *DecisionUpdateOne {
	if i != nil {
		duo.SetSuffixEnd(*i)
	}
	return duo
}

// AddSuffixEnd adds i to the "suffix_end" field.
func (duo *DecisionUpdateOne) AddSuffixEnd(i int64) *DecisionUpdateOne {
	duo.mutation.AddSuffixEnd(i)
	return duo
}

// ClearSuffixEnd clears the value of the "suffix_end" field.
func (duo *DecisionUpdateOne) ClearSuffixEnd() *DecisionUpdateOne {
	duo.mutation.ClearSuffixEnd()
	return duo
}

// SetScope sets the "scope" field.
func (duo *DecisionUpdateOne) SetScope(s string) *DecisionUpdateOne {
	duo.mutation.SetScope(s)
	return duo
}

// SetValue sets the "value" field.
func (duo *DecisionUpdateOne) SetValue(s string) *DecisionUpdateOne {
	duo.mutation.SetValue(s)
	return duo
}

// SetOrigin sets the "origin" field.
func (duo *DecisionUpdateOne) SetOrigin(s string) *DecisionUpdateOne {
	duo.mutation.SetOrigin(s)
	return duo
}

// SetSimulated sets the "simulated" field.
func (duo *DecisionUpdateOne) SetSimulated(b bool) *DecisionUpdateOne {
	duo.mutation.SetSimulated(b)
	return duo
}

// SetNillableSimulated sets the "simulated" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableSimulated(b *bool) *DecisionUpdateOne {
	if b != nil {
		duo.SetSimulated(*b)
	}
	return duo
}

// SetOwnerID sets the "owner" edge to the Alert entity by ID.
func (duo *DecisionUpdateOne) SetOwnerID(id int) *DecisionUpdateOne {
	duo.mutation.SetOwnerID(id)
	return duo
}

// SetNillableOwnerID sets the "owner" edge to the Alert entity by ID if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableOwnerID(id *int) *DecisionUpdateOne {
	if id != nil {
		duo = duo.SetOwnerID(*id)
	}
	return duo
}

// SetOwner sets the "owner" edge to the Alert entity.
func (duo *DecisionUpdateOne) SetOwner(a *Alert) *DecisionUpdateOne {
	return duo.SetOwnerID(a.ID)
}

// Mutation returns the DecisionMutation object of the builder.
func (duo *DecisionUpdateOne) Mutation() *DecisionMutation {
	return duo.mutation
}

// ClearOwner clears the "owner" edge to the Alert entity.
func (duo *DecisionUpdateOne) ClearOwner() *DecisionUpdateOne {
	duo.mutation.ClearOwner()
	return duo
}

// Save executes the query and returns the updated Decision entity.
func (duo *DecisionUpdateOne) Save(ctx context.Context) (*Decision, error) {
	var (
		err  error
		node *Decision
	)
	if len(duo.hooks) == 0 {
		node, err = duo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*DecisionMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			duo.mutation = mutation
			node, err = duo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(duo.hooks) - 1; i >= 0; i-- {
			mut = duo.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, duo.mutation); err != nil {
			return nil, err
		}
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (duo *DecisionUpdateOne) SaveX(ctx context.Context) *Decision {
	node, err := duo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (duo *DecisionUpdateOne) Exec(ctx context.Context) error {
	_, err := duo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (duo *DecisionUpdateOne) ExecX(ctx context.Context) {
	if err := duo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (duo *DecisionUpdateOne) sqlSave(ctx context.Context) (_node *Decision, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   decision.Table,
			Columns: decision.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: decision.FieldID,
			},
		},
	}
	id, ok := duo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "ID", err: fmt.Errorf("missing Decision.ID for update")}
	}
	_spec.Node.ID.Value = id
	if value, ok := duo.mutation.CreatedAt(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: decision.FieldCreatedAt,
		})
	}
	if value, ok := duo.mutation.UpdatedAt(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: decision.FieldUpdatedAt,
		})
	}
	if value, ok := duo.mutation.Until(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: decision.FieldUntil,
		})
	}
	if value, ok := duo.mutation.Scenario(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: decision.FieldScenario,
		})
	}
	if value, ok := duo.mutation.GetType(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: decision.FieldType,
		})
	}
	if value, ok := duo.mutation.StartIP(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldStartIP,
		})
	}
	if value, ok := duo.mutation.AddedStartIP(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldStartIP,
		})
	}
	if duo.mutation.StartIPCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Column: decision.FieldStartIP,
		})
	}
	if value, ok := duo.mutation.EndIP(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldEndIP,
		})
	}
	if value, ok := duo.mutation.AddedEndIP(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldEndIP,
		})
	}
	if duo.mutation.EndIPCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Column: decision.FieldEndIP,
		})
	}
	if value, ok := duo.mutation.RangeStart(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldRangeStart,
		})
	}
	if value, ok := duo.mutation.AddedRangeStart(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldRangeStart,
		})
	}
	if duo.mutation.RangeStartCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Column: decision.FieldRangeStart,
		})
	}
	if value, ok := duo.mutation.RangeEnd(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldRangeEnd,
		})
	}
	if value, ok := duo.mutation.AddedRangeEnd(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldRangeEnd,
		})
	}
	if duo.mutation.RangeEndCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Column: decision.FieldRangeEnd,
		})
	}
	if value, ok := duo.mutation.SuffixStart(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldSuffixStart,
		})
	}
	if value, ok := duo.mutation.AddedSuffixStart(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldSuffixStart,
		})
	}
	if duo.mutation.SuffixStartCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Column: decision.FieldSuffixStart,
		})
	}
	if value, ok := duo.mutation.SuffixEnd(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldSuffixEnd,
		})
	}
	if value, ok := duo.mutation.AddedSuffixEnd(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: decision.FieldSuffixEnd,
		})
	}
	if duo.mutation.SuffixEndCleared() {
		_spec.Fields.Clear = append(_spec.Fields.Clear, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Column: decision.FieldSuffixEnd,
		})
	}
	if value, ok := duo.mutation.Scope(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: decision.FieldScope,
		})
	}
	if value, ok := duo.mutation.Value(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: decision.FieldValue,
		})
	}
	if value, ok := duo.mutation.Origin(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: decision.FieldOrigin,
		})
	}
	if value, ok := duo.mutation.Simulated(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeBool,
			Value:  value,
			Column: decision.FieldSimulated,
		})
	}
	if duo.mutation.OwnerCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   decision.OwnerTable,
			Columns: []string{decision.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: alert.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := duo.mutation.OwnerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   decision.OwnerTable,
			Columns: []string{decision.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: alert.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &Decision{config: duo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, duo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{decision.Label}
		} else if cerr, ok := isSQLConstraintError(err); ok {
			err = cerr
		}
		return nil, err
	}
	return _node, nil
}
