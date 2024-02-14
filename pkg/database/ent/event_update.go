// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/event"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
)

// EventUpdate is the builder for updating Event entities.
type EventUpdate struct {
	config
	hooks    []Hook
	mutation *EventMutation
}

// Where appends a list predicates to the EventUpdate builder.
func (eu *EventUpdate) Where(ps ...predicate.Event) *EventUpdate {
	eu.mutation.Where(ps...)
	return eu
}

// SetCreatedAt sets the "created_at" field.
func (eu *EventUpdate) SetCreatedAt(t time.Time) *EventUpdate {
	eu.mutation.SetCreatedAt(t)
	return eu
}

// ClearCreatedAt clears the value of the "created_at" field.
func (eu *EventUpdate) ClearCreatedAt() *EventUpdate {
	eu.mutation.ClearCreatedAt()
	return eu
}

// SetUpdatedAt sets the "updated_at" field.
func (eu *EventUpdate) SetUpdatedAt(t time.Time) *EventUpdate {
	eu.mutation.SetUpdatedAt(t)
	return eu
}

// ClearUpdatedAt clears the value of the "updated_at" field.
func (eu *EventUpdate) ClearUpdatedAt() *EventUpdate {
	eu.mutation.ClearUpdatedAt()
	return eu
}

// SetTime sets the "time" field.
func (eu *EventUpdate) SetTime(t time.Time) *EventUpdate {
	eu.mutation.SetTime(t)
	return eu
}

// SetSerialized sets the "serialized" field.
func (eu *EventUpdate) SetSerialized(s string) *EventUpdate {
	eu.mutation.SetSerialized(s)
	return eu
}

// SetAlertEvents sets the "alert_events" field.
func (eu *EventUpdate) SetAlertEvents(i int) *EventUpdate {
	eu.mutation.SetAlertEvents(i)
	return eu
}

// SetNillableAlertEvents sets the "alert_events" field if the given value is not nil.
func (eu *EventUpdate) SetNillableAlertEvents(i *int) *EventUpdate {
	if i != nil {
		eu.SetAlertEvents(*i)
	}
	return eu
}

// ClearAlertEvents clears the value of the "alert_events" field.
func (eu *EventUpdate) ClearAlertEvents() *EventUpdate {
	eu.mutation.ClearAlertEvents()
	return eu
}

// SetOwnerID sets the "owner" edge to the Alert entity by ID.
func (eu *EventUpdate) SetOwnerID(id int) *EventUpdate {
	eu.mutation.SetOwnerID(id)
	return eu
}

// SetNillableOwnerID sets the "owner" edge to the Alert entity by ID if the given value is not nil.
func (eu *EventUpdate) SetNillableOwnerID(id *int) *EventUpdate {
	if id != nil {
		eu = eu.SetOwnerID(*id)
	}
	return eu
}

// SetOwner sets the "owner" edge to the Alert entity.
func (eu *EventUpdate) SetOwner(a *Alert) *EventUpdate {
	return eu.SetOwnerID(a.ID)
}

// Mutation returns the EventMutation object of the builder.
func (eu *EventUpdate) Mutation() *EventMutation {
	return eu.mutation
}

// ClearOwner clears the "owner" edge to the Alert entity.
func (eu *EventUpdate) ClearOwner() *EventUpdate {
	eu.mutation.ClearOwner()
	return eu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (eu *EventUpdate) Save(ctx context.Context) (int, error) {
	eu.defaults()
	return withHooks(ctx, eu.sqlSave, eu.mutation, eu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (eu *EventUpdate) SaveX(ctx context.Context) int {
	affected, err := eu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (eu *EventUpdate) Exec(ctx context.Context) error {
	_, err := eu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (eu *EventUpdate) ExecX(ctx context.Context) {
	if err := eu.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (eu *EventUpdate) defaults() {
	if _, ok := eu.mutation.CreatedAt(); !ok && !eu.mutation.CreatedAtCleared() {
		v := event.UpdateDefaultCreatedAt()
		eu.mutation.SetCreatedAt(v)
	}
	if _, ok := eu.mutation.UpdatedAt(); !ok && !eu.mutation.UpdatedAtCleared() {
		v := event.UpdateDefaultUpdatedAt()
		eu.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (eu *EventUpdate) check() error {
	if v, ok := eu.mutation.Serialized(); ok {
		if err := event.SerializedValidator(v); err != nil {
			return &ValidationError{Name: "serialized", err: fmt.Errorf(`ent: validator failed for field "Event.serialized": %w`, err)}
		}
	}
	return nil
}

func (eu *EventUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := eu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(event.Table, event.Columns, sqlgraph.NewFieldSpec(event.FieldID, field.TypeInt))
	if ps := eu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := eu.mutation.CreatedAt(); ok {
		_spec.SetField(event.FieldCreatedAt, field.TypeTime, value)
	}
	if eu.mutation.CreatedAtCleared() {
		_spec.ClearField(event.FieldCreatedAt, field.TypeTime)
	}
	if value, ok := eu.mutation.UpdatedAt(); ok {
		_spec.SetField(event.FieldUpdatedAt, field.TypeTime, value)
	}
	if eu.mutation.UpdatedAtCleared() {
		_spec.ClearField(event.FieldUpdatedAt, field.TypeTime)
	}
	if value, ok := eu.mutation.Time(); ok {
		_spec.SetField(event.FieldTime, field.TypeTime, value)
	}
	if value, ok := eu.mutation.Serialized(); ok {
		_spec.SetField(event.FieldSerialized, field.TypeString, value)
	}
	if eu.mutation.OwnerCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   event.OwnerTable,
			Columns: []string{event.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(alert.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := eu.mutation.OwnerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   event.OwnerTable,
			Columns: []string{event.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(alert.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, eu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{event.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	eu.mutation.done = true
	return n, nil
}

// EventUpdateOne is the builder for updating a single Event entity.
type EventUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *EventMutation
}

// SetCreatedAt sets the "created_at" field.
func (euo *EventUpdateOne) SetCreatedAt(t time.Time) *EventUpdateOne {
	euo.mutation.SetCreatedAt(t)
	return euo
}

// ClearCreatedAt clears the value of the "created_at" field.
func (euo *EventUpdateOne) ClearCreatedAt() *EventUpdateOne {
	euo.mutation.ClearCreatedAt()
	return euo
}

// SetUpdatedAt sets the "updated_at" field.
func (euo *EventUpdateOne) SetUpdatedAt(t time.Time) *EventUpdateOne {
	euo.mutation.SetUpdatedAt(t)
	return euo
}

// ClearUpdatedAt clears the value of the "updated_at" field.
func (euo *EventUpdateOne) ClearUpdatedAt() *EventUpdateOne {
	euo.mutation.ClearUpdatedAt()
	return euo
}

// SetTime sets the "time" field.
func (euo *EventUpdateOne) SetTime(t time.Time) *EventUpdateOne {
	euo.mutation.SetTime(t)
	return euo
}

// SetSerialized sets the "serialized" field.
func (euo *EventUpdateOne) SetSerialized(s string) *EventUpdateOne {
	euo.mutation.SetSerialized(s)
	return euo
}

// SetAlertEvents sets the "alert_events" field.
func (euo *EventUpdateOne) SetAlertEvents(i int) *EventUpdateOne {
	euo.mutation.SetAlertEvents(i)
	return euo
}

// SetNillableAlertEvents sets the "alert_events" field if the given value is not nil.
func (euo *EventUpdateOne) SetNillableAlertEvents(i *int) *EventUpdateOne {
	if i != nil {
		euo.SetAlertEvents(*i)
	}
	return euo
}

// ClearAlertEvents clears the value of the "alert_events" field.
func (euo *EventUpdateOne) ClearAlertEvents() *EventUpdateOne {
	euo.mutation.ClearAlertEvents()
	return euo
}

// SetOwnerID sets the "owner" edge to the Alert entity by ID.
func (euo *EventUpdateOne) SetOwnerID(id int) *EventUpdateOne {
	euo.mutation.SetOwnerID(id)
	return euo
}

// SetNillableOwnerID sets the "owner" edge to the Alert entity by ID if the given value is not nil.
func (euo *EventUpdateOne) SetNillableOwnerID(id *int) *EventUpdateOne {
	if id != nil {
		euo = euo.SetOwnerID(*id)
	}
	return euo
}

// SetOwner sets the "owner" edge to the Alert entity.
func (euo *EventUpdateOne) SetOwner(a *Alert) *EventUpdateOne {
	return euo.SetOwnerID(a.ID)
}

// Mutation returns the EventMutation object of the builder.
func (euo *EventUpdateOne) Mutation() *EventMutation {
	return euo.mutation
}

// ClearOwner clears the "owner" edge to the Alert entity.
func (euo *EventUpdateOne) ClearOwner() *EventUpdateOne {
	euo.mutation.ClearOwner()
	return euo
}

// Where appends a list predicates to the EventUpdate builder.
func (euo *EventUpdateOne) Where(ps ...predicate.Event) *EventUpdateOne {
	euo.mutation.Where(ps...)
	return euo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (euo *EventUpdateOne) Select(field string, fields ...string) *EventUpdateOne {
	euo.fields = append([]string{field}, fields...)
	return euo
}

// Save executes the query and returns the updated Event entity.
func (euo *EventUpdateOne) Save(ctx context.Context) (*Event, error) {
	euo.defaults()
	return withHooks(ctx, euo.sqlSave, euo.mutation, euo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (euo *EventUpdateOne) SaveX(ctx context.Context) *Event {
	node, err := euo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (euo *EventUpdateOne) Exec(ctx context.Context) error {
	_, err := euo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (euo *EventUpdateOne) ExecX(ctx context.Context) {
	if err := euo.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (euo *EventUpdateOne) defaults() {
	if _, ok := euo.mutation.CreatedAt(); !ok && !euo.mutation.CreatedAtCleared() {
		v := event.UpdateDefaultCreatedAt()
		euo.mutation.SetCreatedAt(v)
	}
	if _, ok := euo.mutation.UpdatedAt(); !ok && !euo.mutation.UpdatedAtCleared() {
		v := event.UpdateDefaultUpdatedAt()
		euo.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (euo *EventUpdateOne) check() error {
	if v, ok := euo.mutation.Serialized(); ok {
		if err := event.SerializedValidator(v); err != nil {
			return &ValidationError{Name: "serialized", err: fmt.Errorf(`ent: validator failed for field "Event.serialized": %w`, err)}
		}
	}
	return nil
}

func (euo *EventUpdateOne) sqlSave(ctx context.Context) (_node *Event, err error) {
	if err := euo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(event.Table, event.Columns, sqlgraph.NewFieldSpec(event.FieldID, field.TypeInt))
	id, ok := euo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Event.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := euo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, event.FieldID)
		for _, f := range fields {
			if !event.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != event.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := euo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := euo.mutation.CreatedAt(); ok {
		_spec.SetField(event.FieldCreatedAt, field.TypeTime, value)
	}
	if euo.mutation.CreatedAtCleared() {
		_spec.ClearField(event.FieldCreatedAt, field.TypeTime)
	}
	if value, ok := euo.mutation.UpdatedAt(); ok {
		_spec.SetField(event.FieldUpdatedAt, field.TypeTime, value)
	}
	if euo.mutation.UpdatedAtCleared() {
		_spec.ClearField(event.FieldUpdatedAt, field.TypeTime)
	}
	if value, ok := euo.mutation.Time(); ok {
		_spec.SetField(event.FieldTime, field.TypeTime, value)
	}
	if value, ok := euo.mutation.Serialized(); ok {
		_spec.SetField(event.FieldSerialized, field.TypeString, value)
	}
	if euo.mutation.OwnerCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   event.OwnerTable,
			Columns: []string{event.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(alert.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := euo.mutation.OwnerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   event.OwnerTable,
			Columns: []string{event.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(alert.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &Event{config: euo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, euo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{event.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	euo.mutation.done = true
	return _node, nil
}
