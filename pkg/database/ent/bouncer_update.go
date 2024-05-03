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
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/bouncer"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
)

// BouncerUpdate is the builder for updating Bouncer entities.
type BouncerUpdate struct {
	config
	hooks    []Hook
	mutation *BouncerMutation
}

// Where appends a list predicates to the BouncerUpdate builder.
func (bu *BouncerUpdate) Where(ps ...predicate.Bouncer) *BouncerUpdate {
	bu.mutation.Where(ps...)
	return bu
}

// SetCreatedAt sets the "created_at" field.
func (bu *BouncerUpdate) SetCreatedAt(t time.Time) *BouncerUpdate {
	bu.mutation.SetCreatedAt(t)
	return bu
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (bu *BouncerUpdate) SetNillableCreatedAt(t *time.Time) *BouncerUpdate {
	if t != nil {
		bu.SetCreatedAt(*t)
	}
	return bu
}

// SetUpdatedAt sets the "updated_at" field.
func (bu *BouncerUpdate) SetUpdatedAt(t time.Time) *BouncerUpdate {
	bu.mutation.SetUpdatedAt(t)
	return bu
}

// SetName sets the "name" field.
func (bu *BouncerUpdate) SetName(s string) *BouncerUpdate {
	bu.mutation.SetName(s)
	return bu
}

// SetNillableName sets the "name" field if the given value is not nil.
func (bu *BouncerUpdate) SetNillableName(s *string) *BouncerUpdate {
	if s != nil {
		bu.SetName(*s)
	}
	return bu
}

// SetAPIKey sets the "api_key" field.
func (bu *BouncerUpdate) SetAPIKey(s string) *BouncerUpdate {
	bu.mutation.SetAPIKey(s)
	return bu
}

// SetNillableAPIKey sets the "api_key" field if the given value is not nil.
func (bu *BouncerUpdate) SetNillableAPIKey(s *string) *BouncerUpdate {
	if s != nil {
		bu.SetAPIKey(*s)
	}
	return bu
}

// SetRevoked sets the "revoked" field.
func (bu *BouncerUpdate) SetRevoked(b bool) *BouncerUpdate {
	bu.mutation.SetRevoked(b)
	return bu
}

// SetNillableRevoked sets the "revoked" field if the given value is not nil.
func (bu *BouncerUpdate) SetNillableRevoked(b *bool) *BouncerUpdate {
	if b != nil {
		bu.SetRevoked(*b)
	}
	return bu
}

// SetIPAddress sets the "ip_address" field.
func (bu *BouncerUpdate) SetIPAddress(s string) *BouncerUpdate {
	bu.mutation.SetIPAddress(s)
	return bu
}

// SetNillableIPAddress sets the "ip_address" field if the given value is not nil.
func (bu *BouncerUpdate) SetNillableIPAddress(s *string) *BouncerUpdate {
	if s != nil {
		bu.SetIPAddress(*s)
	}
	return bu
}

// ClearIPAddress clears the value of the "ip_address" field.
func (bu *BouncerUpdate) ClearIPAddress() *BouncerUpdate {
	bu.mutation.ClearIPAddress()
	return bu
}

// SetType sets the "type" field.
func (bu *BouncerUpdate) SetType(s string) *BouncerUpdate {
	bu.mutation.SetType(s)
	return bu
}

// SetNillableType sets the "type" field if the given value is not nil.
func (bu *BouncerUpdate) SetNillableType(s *string) *BouncerUpdate {
	if s != nil {
		bu.SetType(*s)
	}
	return bu
}

// ClearType clears the value of the "type" field.
func (bu *BouncerUpdate) ClearType() *BouncerUpdate {
	bu.mutation.ClearType()
	return bu
}

// SetVersion sets the "version" field.
func (bu *BouncerUpdate) SetVersion(s string) *BouncerUpdate {
	bu.mutation.SetVersion(s)
	return bu
}

// SetNillableVersion sets the "version" field if the given value is not nil.
func (bu *BouncerUpdate) SetNillableVersion(s *string) *BouncerUpdate {
	if s != nil {
		bu.SetVersion(*s)
	}
	return bu
}

// ClearVersion clears the value of the "version" field.
func (bu *BouncerUpdate) ClearVersion() *BouncerUpdate {
	bu.mutation.ClearVersion()
	return bu
}

// SetUntil sets the "until" field.
func (bu *BouncerUpdate) SetUntil(t time.Time) *BouncerUpdate {
	bu.mutation.SetUntil(t)
	return bu
}

// SetNillableUntil sets the "until" field if the given value is not nil.
func (bu *BouncerUpdate) SetNillableUntil(t *time.Time) *BouncerUpdate {
	if t != nil {
		bu.SetUntil(*t)
	}
	return bu
}

// ClearUntil clears the value of the "until" field.
func (bu *BouncerUpdate) ClearUntil() *BouncerUpdate {
	bu.mutation.ClearUntil()
	return bu
}

// SetLastPull sets the "last_pull" field.
func (bu *BouncerUpdate) SetLastPull(t time.Time) *BouncerUpdate {
	bu.mutation.SetLastPull(t)
	return bu
}

// SetNillableLastPull sets the "last_pull" field if the given value is not nil.
func (bu *BouncerUpdate) SetNillableLastPull(t *time.Time) *BouncerUpdate {
	if t != nil {
		bu.SetLastPull(*t)
	}
	return bu
}

// SetAuthType sets the "auth_type" field.
func (bu *BouncerUpdate) SetAuthType(s string) *BouncerUpdate {
	bu.mutation.SetAuthType(s)
	return bu
}

// SetNillableAuthType sets the "auth_type" field if the given value is not nil.
func (bu *BouncerUpdate) SetNillableAuthType(s *string) *BouncerUpdate {
	if s != nil {
		bu.SetAuthType(*s)
	}
	return bu
}

// Mutation returns the BouncerMutation object of the builder.
func (bu *BouncerUpdate) Mutation() *BouncerMutation {
	return bu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (bu *BouncerUpdate) Save(ctx context.Context) (int, error) {
	bu.defaults()
	return withHooks(ctx, bu.sqlSave, bu.mutation, bu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (bu *BouncerUpdate) SaveX(ctx context.Context) int {
	affected, err := bu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (bu *BouncerUpdate) Exec(ctx context.Context) error {
	_, err := bu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (bu *BouncerUpdate) ExecX(ctx context.Context) {
	if err := bu.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (bu *BouncerUpdate) defaults() {
	if _, ok := bu.mutation.UpdatedAt(); !ok {
		v := bouncer.UpdateDefaultUpdatedAt()
		bu.mutation.SetUpdatedAt(v)
	}
}

func (bu *BouncerUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(bouncer.Table, bouncer.Columns, sqlgraph.NewFieldSpec(bouncer.FieldID, field.TypeInt))
	if ps := bu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := bu.mutation.CreatedAt(); ok {
		_spec.SetField(bouncer.FieldCreatedAt, field.TypeTime, value)
	}
	if value, ok := bu.mutation.UpdatedAt(); ok {
		_spec.SetField(bouncer.FieldUpdatedAt, field.TypeTime, value)
	}
	if value, ok := bu.mutation.Name(); ok {
		_spec.SetField(bouncer.FieldName, field.TypeString, value)
	}
	if value, ok := bu.mutation.APIKey(); ok {
		_spec.SetField(bouncer.FieldAPIKey, field.TypeString, value)
	}
	if value, ok := bu.mutation.Revoked(); ok {
		_spec.SetField(bouncer.FieldRevoked, field.TypeBool, value)
	}
	if value, ok := bu.mutation.IPAddress(); ok {
		_spec.SetField(bouncer.FieldIPAddress, field.TypeString, value)
	}
	if bu.mutation.IPAddressCleared() {
		_spec.ClearField(bouncer.FieldIPAddress, field.TypeString)
	}
	if value, ok := bu.mutation.GetType(); ok {
		_spec.SetField(bouncer.FieldType, field.TypeString, value)
	}
	if bu.mutation.TypeCleared() {
		_spec.ClearField(bouncer.FieldType, field.TypeString)
	}
	if value, ok := bu.mutation.Version(); ok {
		_spec.SetField(bouncer.FieldVersion, field.TypeString, value)
	}
	if bu.mutation.VersionCleared() {
		_spec.ClearField(bouncer.FieldVersion, field.TypeString)
	}
	if value, ok := bu.mutation.Until(); ok {
		_spec.SetField(bouncer.FieldUntil, field.TypeTime, value)
	}
	if bu.mutation.UntilCleared() {
		_spec.ClearField(bouncer.FieldUntil, field.TypeTime)
	}
	if value, ok := bu.mutation.LastPull(); ok {
		_spec.SetField(bouncer.FieldLastPull, field.TypeTime, value)
	}
	if value, ok := bu.mutation.AuthType(); ok {
		_spec.SetField(bouncer.FieldAuthType, field.TypeString, value)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, bu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{bouncer.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	bu.mutation.done = true
	return n, nil
}

// BouncerUpdateOne is the builder for updating a single Bouncer entity.
type BouncerUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *BouncerMutation
}

// SetCreatedAt sets the "created_at" field.
func (buo *BouncerUpdateOne) SetCreatedAt(t time.Time) *BouncerUpdateOne {
	buo.mutation.SetCreatedAt(t)
	return buo
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (buo *BouncerUpdateOne) SetNillableCreatedAt(t *time.Time) *BouncerUpdateOne {
	if t != nil {
		buo.SetCreatedAt(*t)
	}
	return buo
}

// SetUpdatedAt sets the "updated_at" field.
func (buo *BouncerUpdateOne) SetUpdatedAt(t time.Time) *BouncerUpdateOne {
	buo.mutation.SetUpdatedAt(t)
	return buo
}

// SetName sets the "name" field.
func (buo *BouncerUpdateOne) SetName(s string) *BouncerUpdateOne {
	buo.mutation.SetName(s)
	return buo
}

// SetNillableName sets the "name" field if the given value is not nil.
func (buo *BouncerUpdateOne) SetNillableName(s *string) *BouncerUpdateOne {
	if s != nil {
		buo.SetName(*s)
	}
	return buo
}

// SetAPIKey sets the "api_key" field.
func (buo *BouncerUpdateOne) SetAPIKey(s string) *BouncerUpdateOne {
	buo.mutation.SetAPIKey(s)
	return buo
}

// SetNillableAPIKey sets the "api_key" field if the given value is not nil.
func (buo *BouncerUpdateOne) SetNillableAPIKey(s *string) *BouncerUpdateOne {
	if s != nil {
		buo.SetAPIKey(*s)
	}
	return buo
}

// SetRevoked sets the "revoked" field.
func (buo *BouncerUpdateOne) SetRevoked(b bool) *BouncerUpdateOne {
	buo.mutation.SetRevoked(b)
	return buo
}

// SetNillableRevoked sets the "revoked" field if the given value is not nil.
func (buo *BouncerUpdateOne) SetNillableRevoked(b *bool) *BouncerUpdateOne {
	if b != nil {
		buo.SetRevoked(*b)
	}
	return buo
}

// SetIPAddress sets the "ip_address" field.
func (buo *BouncerUpdateOne) SetIPAddress(s string) *BouncerUpdateOne {
	buo.mutation.SetIPAddress(s)
	return buo
}

// SetNillableIPAddress sets the "ip_address" field if the given value is not nil.
func (buo *BouncerUpdateOne) SetNillableIPAddress(s *string) *BouncerUpdateOne {
	if s != nil {
		buo.SetIPAddress(*s)
	}
	return buo
}

// ClearIPAddress clears the value of the "ip_address" field.
func (buo *BouncerUpdateOne) ClearIPAddress() *BouncerUpdateOne {
	buo.mutation.ClearIPAddress()
	return buo
}

// SetType sets the "type" field.
func (buo *BouncerUpdateOne) SetType(s string) *BouncerUpdateOne {
	buo.mutation.SetType(s)
	return buo
}

// SetNillableType sets the "type" field if the given value is not nil.
func (buo *BouncerUpdateOne) SetNillableType(s *string) *BouncerUpdateOne {
	if s != nil {
		buo.SetType(*s)
	}
	return buo
}

// ClearType clears the value of the "type" field.
func (buo *BouncerUpdateOne) ClearType() *BouncerUpdateOne {
	buo.mutation.ClearType()
	return buo
}

// SetVersion sets the "version" field.
func (buo *BouncerUpdateOne) SetVersion(s string) *BouncerUpdateOne {
	buo.mutation.SetVersion(s)
	return buo
}

// SetNillableVersion sets the "version" field if the given value is not nil.
func (buo *BouncerUpdateOne) SetNillableVersion(s *string) *BouncerUpdateOne {
	if s != nil {
		buo.SetVersion(*s)
	}
	return buo
}

// ClearVersion clears the value of the "version" field.
func (buo *BouncerUpdateOne) ClearVersion() *BouncerUpdateOne {
	buo.mutation.ClearVersion()
	return buo
}

// SetUntil sets the "until" field.
func (buo *BouncerUpdateOne) SetUntil(t time.Time) *BouncerUpdateOne {
	buo.mutation.SetUntil(t)
	return buo
}

// SetNillableUntil sets the "until" field if the given value is not nil.
func (buo *BouncerUpdateOne) SetNillableUntil(t *time.Time) *BouncerUpdateOne {
	if t != nil {
		buo.SetUntil(*t)
	}
	return buo
}

// ClearUntil clears the value of the "until" field.
func (buo *BouncerUpdateOne) ClearUntil() *BouncerUpdateOne {
	buo.mutation.ClearUntil()
	return buo
}

// SetLastPull sets the "last_pull" field.
func (buo *BouncerUpdateOne) SetLastPull(t time.Time) *BouncerUpdateOne {
	buo.mutation.SetLastPull(t)
	return buo
}

// SetNillableLastPull sets the "last_pull" field if the given value is not nil.
func (buo *BouncerUpdateOne) SetNillableLastPull(t *time.Time) *BouncerUpdateOne {
	if t != nil {
		buo.SetLastPull(*t)
	}
	return buo
}

// SetAuthType sets the "auth_type" field.
func (buo *BouncerUpdateOne) SetAuthType(s string) *BouncerUpdateOne {
	buo.mutation.SetAuthType(s)
	return buo
}

// SetNillableAuthType sets the "auth_type" field if the given value is not nil.
func (buo *BouncerUpdateOne) SetNillableAuthType(s *string) *BouncerUpdateOne {
	if s != nil {
		buo.SetAuthType(*s)
	}
	return buo
}

// Mutation returns the BouncerMutation object of the builder.
func (buo *BouncerUpdateOne) Mutation() *BouncerMutation {
	return buo.mutation
}

// Where appends a list predicates to the BouncerUpdate builder.
func (buo *BouncerUpdateOne) Where(ps ...predicate.Bouncer) *BouncerUpdateOne {
	buo.mutation.Where(ps...)
	return buo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (buo *BouncerUpdateOne) Select(field string, fields ...string) *BouncerUpdateOne {
	buo.fields = append([]string{field}, fields...)
	return buo
}

// Save executes the query and returns the updated Bouncer entity.
func (buo *BouncerUpdateOne) Save(ctx context.Context) (*Bouncer, error) {
	buo.defaults()
	return withHooks(ctx, buo.sqlSave, buo.mutation, buo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (buo *BouncerUpdateOne) SaveX(ctx context.Context) *Bouncer {
	node, err := buo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (buo *BouncerUpdateOne) Exec(ctx context.Context) error {
	_, err := buo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (buo *BouncerUpdateOne) ExecX(ctx context.Context) {
	if err := buo.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (buo *BouncerUpdateOne) defaults() {
	if _, ok := buo.mutation.UpdatedAt(); !ok {
		v := bouncer.UpdateDefaultUpdatedAt()
		buo.mutation.SetUpdatedAt(v)
	}
}

func (buo *BouncerUpdateOne) sqlSave(ctx context.Context) (_node *Bouncer, err error) {
	_spec := sqlgraph.NewUpdateSpec(bouncer.Table, bouncer.Columns, sqlgraph.NewFieldSpec(bouncer.FieldID, field.TypeInt))
	id, ok := buo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Bouncer.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := buo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, bouncer.FieldID)
		for _, f := range fields {
			if !bouncer.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != bouncer.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := buo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := buo.mutation.CreatedAt(); ok {
		_spec.SetField(bouncer.FieldCreatedAt, field.TypeTime, value)
	}
	if value, ok := buo.mutation.UpdatedAt(); ok {
		_spec.SetField(bouncer.FieldUpdatedAt, field.TypeTime, value)
	}
	if value, ok := buo.mutation.Name(); ok {
		_spec.SetField(bouncer.FieldName, field.TypeString, value)
	}
	if value, ok := buo.mutation.APIKey(); ok {
		_spec.SetField(bouncer.FieldAPIKey, field.TypeString, value)
	}
	if value, ok := buo.mutation.Revoked(); ok {
		_spec.SetField(bouncer.FieldRevoked, field.TypeBool, value)
	}
	if value, ok := buo.mutation.IPAddress(); ok {
		_spec.SetField(bouncer.FieldIPAddress, field.TypeString, value)
	}
	if buo.mutation.IPAddressCleared() {
		_spec.ClearField(bouncer.FieldIPAddress, field.TypeString)
	}
	if value, ok := buo.mutation.GetType(); ok {
		_spec.SetField(bouncer.FieldType, field.TypeString, value)
	}
	if buo.mutation.TypeCleared() {
		_spec.ClearField(bouncer.FieldType, field.TypeString)
	}
	if value, ok := buo.mutation.Version(); ok {
		_spec.SetField(bouncer.FieldVersion, field.TypeString, value)
	}
	if buo.mutation.VersionCleared() {
		_spec.ClearField(bouncer.FieldVersion, field.TypeString)
	}
	if value, ok := buo.mutation.Until(); ok {
		_spec.SetField(bouncer.FieldUntil, field.TypeTime, value)
	}
	if buo.mutation.UntilCleared() {
		_spec.ClearField(bouncer.FieldUntil, field.TypeTime)
	}
	if value, ok := buo.mutation.LastPull(); ok {
		_spec.SetField(bouncer.FieldLastPull, field.TypeTime, value)
	}
	if value, ok := buo.mutation.AuthType(); ok {
		_spec.SetField(bouncer.FieldAuthType, field.TypeString, value)
	}
	_node = &Bouncer{config: buo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, buo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{bouncer.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	buo.mutation.done = true
	return _node, nil
}
