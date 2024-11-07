// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"database/sql/driver"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/allowlist"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/allowlistitem"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
)

// AllowListQuery is the builder for querying AllowList entities.
type AllowListQuery struct {
	config
	ctx                *QueryContext
	order              []allowlist.OrderOption
	inters             []Interceptor
	predicates         []predicate.AllowList
	withAllowlistItems *AllowListItemQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the AllowListQuery builder.
func (alq *AllowListQuery) Where(ps ...predicate.AllowList) *AllowListQuery {
	alq.predicates = append(alq.predicates, ps...)
	return alq
}

// Limit the number of records to be returned by this query.
func (alq *AllowListQuery) Limit(limit int) *AllowListQuery {
	alq.ctx.Limit = &limit
	return alq
}

// Offset to start from.
func (alq *AllowListQuery) Offset(offset int) *AllowListQuery {
	alq.ctx.Offset = &offset
	return alq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (alq *AllowListQuery) Unique(unique bool) *AllowListQuery {
	alq.ctx.Unique = &unique
	return alq
}

// Order specifies how the records should be ordered.
func (alq *AllowListQuery) Order(o ...allowlist.OrderOption) *AllowListQuery {
	alq.order = append(alq.order, o...)
	return alq
}

// QueryAllowlistItems chains the current query on the "allowlist_items" edge.
func (alq *AllowListQuery) QueryAllowlistItems() *AllowListItemQuery {
	query := (&AllowListItemClient{config: alq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := alq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := alq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(allowlist.Table, allowlist.FieldID, selector),
			sqlgraph.To(allowlistitem.Table, allowlistitem.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, allowlist.AllowlistItemsTable, allowlist.AllowlistItemsPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(alq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first AllowList entity from the query.
// Returns a *NotFoundError when no AllowList was found.
func (alq *AllowListQuery) First(ctx context.Context) (*AllowList, error) {
	nodes, err := alq.Limit(1).All(setContextOp(ctx, alq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{allowlist.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (alq *AllowListQuery) FirstX(ctx context.Context) *AllowList {
	node, err := alq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first AllowList ID from the query.
// Returns a *NotFoundError when no AllowList ID was found.
func (alq *AllowListQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = alq.Limit(1).IDs(setContextOp(ctx, alq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{allowlist.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (alq *AllowListQuery) FirstIDX(ctx context.Context) int {
	id, err := alq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single AllowList entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one AllowList entity is found.
// Returns a *NotFoundError when no AllowList entities are found.
func (alq *AllowListQuery) Only(ctx context.Context) (*AllowList, error) {
	nodes, err := alq.Limit(2).All(setContextOp(ctx, alq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{allowlist.Label}
	default:
		return nil, &NotSingularError{allowlist.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (alq *AllowListQuery) OnlyX(ctx context.Context) *AllowList {
	node, err := alq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only AllowList ID in the query.
// Returns a *NotSingularError when more than one AllowList ID is found.
// Returns a *NotFoundError when no entities are found.
func (alq *AllowListQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = alq.Limit(2).IDs(setContextOp(ctx, alq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{allowlist.Label}
	default:
		err = &NotSingularError{allowlist.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (alq *AllowListQuery) OnlyIDX(ctx context.Context) int {
	id, err := alq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of AllowLists.
func (alq *AllowListQuery) All(ctx context.Context) ([]*AllowList, error) {
	ctx = setContextOp(ctx, alq.ctx, "All")
	if err := alq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*AllowList, *AllowListQuery]()
	return withInterceptors[[]*AllowList](ctx, alq, qr, alq.inters)
}

// AllX is like All, but panics if an error occurs.
func (alq *AllowListQuery) AllX(ctx context.Context) []*AllowList {
	nodes, err := alq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of AllowList IDs.
func (alq *AllowListQuery) IDs(ctx context.Context) (ids []int, err error) {
	if alq.ctx.Unique == nil && alq.path != nil {
		alq.Unique(true)
	}
	ctx = setContextOp(ctx, alq.ctx, "IDs")
	if err = alq.Select(allowlist.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (alq *AllowListQuery) IDsX(ctx context.Context) []int {
	ids, err := alq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (alq *AllowListQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, alq.ctx, "Count")
	if err := alq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, alq, querierCount[*AllowListQuery](), alq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (alq *AllowListQuery) CountX(ctx context.Context) int {
	count, err := alq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (alq *AllowListQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, alq.ctx, "Exist")
	switch _, err := alq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (alq *AllowListQuery) ExistX(ctx context.Context) bool {
	exist, err := alq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the AllowListQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (alq *AllowListQuery) Clone() *AllowListQuery {
	if alq == nil {
		return nil
	}
	return &AllowListQuery{
		config:             alq.config,
		ctx:                alq.ctx.Clone(),
		order:              append([]allowlist.OrderOption{}, alq.order...),
		inters:             append([]Interceptor{}, alq.inters...),
		predicates:         append([]predicate.AllowList{}, alq.predicates...),
		withAllowlistItems: alq.withAllowlistItems.Clone(),
		// clone intermediate query.
		sql:  alq.sql.Clone(),
		path: alq.path,
	}
}

// WithAllowlistItems tells the query-builder to eager-load the nodes that are connected to
// the "allowlist_items" edge. The optional arguments are used to configure the query builder of the edge.
func (alq *AllowListQuery) WithAllowlistItems(opts ...func(*AllowListItemQuery)) *AllowListQuery {
	query := (&AllowListItemClient{config: alq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	alq.withAllowlistItems = query
	return alq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		CreatedAt time.Time `json:"created_at,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.AllowList.Query().
//		GroupBy(allowlist.FieldCreatedAt).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (alq *AllowListQuery) GroupBy(field string, fields ...string) *AllowListGroupBy {
	alq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &AllowListGroupBy{build: alq}
	grbuild.flds = &alq.ctx.Fields
	grbuild.label = allowlist.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		CreatedAt time.Time `json:"created_at,omitempty"`
//	}
//
//	client.AllowList.Query().
//		Select(allowlist.FieldCreatedAt).
//		Scan(ctx, &v)
func (alq *AllowListQuery) Select(fields ...string) *AllowListSelect {
	alq.ctx.Fields = append(alq.ctx.Fields, fields...)
	sbuild := &AllowListSelect{AllowListQuery: alq}
	sbuild.label = allowlist.Label
	sbuild.flds, sbuild.scan = &alq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a AllowListSelect configured with the given aggregations.
func (alq *AllowListQuery) Aggregate(fns ...AggregateFunc) *AllowListSelect {
	return alq.Select().Aggregate(fns...)
}

func (alq *AllowListQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range alq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, alq); err != nil {
				return err
			}
		}
	}
	for _, f := range alq.ctx.Fields {
		if !allowlist.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if alq.path != nil {
		prev, err := alq.path(ctx)
		if err != nil {
			return err
		}
		alq.sql = prev
	}
	return nil
}

func (alq *AllowListQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*AllowList, error) {
	var (
		nodes       = []*AllowList{}
		_spec       = alq.querySpec()
		loadedTypes = [1]bool{
			alq.withAllowlistItems != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*AllowList).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &AllowList{config: alq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, alq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := alq.withAllowlistItems; query != nil {
		if err := alq.loadAllowlistItems(ctx, query, nodes,
			func(n *AllowList) { n.Edges.AllowlistItems = []*AllowListItem{} },
			func(n *AllowList, e *AllowListItem) { n.Edges.AllowlistItems = append(n.Edges.AllowlistItems, e) }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (alq *AllowListQuery) loadAllowlistItems(ctx context.Context, query *AllowListItemQuery, nodes []*AllowList, init func(*AllowList), assign func(*AllowList, *AllowListItem)) error {
	edgeIDs := make([]driver.Value, len(nodes))
	byID := make(map[int]*AllowList)
	nids := make(map[int]map[*AllowList]struct{})
	for i, node := range nodes {
		edgeIDs[i] = node.ID
		byID[node.ID] = node
		if init != nil {
			init(node)
		}
	}
	query.Where(func(s *sql.Selector) {
		joinT := sql.Table(allowlist.AllowlistItemsTable)
		s.Join(joinT).On(s.C(allowlistitem.FieldID), joinT.C(allowlist.AllowlistItemsPrimaryKey[1]))
		s.Where(sql.InValues(joinT.C(allowlist.AllowlistItemsPrimaryKey[0]), edgeIDs...))
		columns := s.SelectedColumns()
		s.Select(joinT.C(allowlist.AllowlistItemsPrimaryKey[0]))
		s.AppendSelect(columns...)
		s.SetDistinct(false)
	})
	if err := query.prepareQuery(ctx); err != nil {
		return err
	}
	qr := QuerierFunc(func(ctx context.Context, q Query) (Value, error) {
		return query.sqlAll(ctx, func(_ context.Context, spec *sqlgraph.QuerySpec) {
			assign := spec.Assign
			values := spec.ScanValues
			spec.ScanValues = func(columns []string) ([]any, error) {
				values, err := values(columns[1:])
				if err != nil {
					return nil, err
				}
				return append([]any{new(sql.NullInt64)}, values...), nil
			}
			spec.Assign = func(columns []string, values []any) error {
				outValue := int(values[0].(*sql.NullInt64).Int64)
				inValue := int(values[1].(*sql.NullInt64).Int64)
				if nids[inValue] == nil {
					nids[inValue] = map[*AllowList]struct{}{byID[outValue]: {}}
					return assign(columns[1:], values[1:])
				}
				nids[inValue][byID[outValue]] = struct{}{}
				return nil
			}
		})
	})
	neighbors, err := withInterceptors[[]*AllowListItem](ctx, query, qr, query.inters)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected "allowlist_items" node returned %v`, n.ID)
		}
		for kn := range nodes {
			assign(kn, n)
		}
	}
	return nil
}

func (alq *AllowListQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := alq.querySpec()
	_spec.Node.Columns = alq.ctx.Fields
	if len(alq.ctx.Fields) > 0 {
		_spec.Unique = alq.ctx.Unique != nil && *alq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, alq.driver, _spec)
}

func (alq *AllowListQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(allowlist.Table, allowlist.Columns, sqlgraph.NewFieldSpec(allowlist.FieldID, field.TypeInt))
	_spec.From = alq.sql
	if unique := alq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if alq.path != nil {
		_spec.Unique = true
	}
	if fields := alq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, allowlist.FieldID)
		for i := range fields {
			if fields[i] != allowlist.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := alq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := alq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := alq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := alq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (alq *AllowListQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(alq.driver.Dialect())
	t1 := builder.Table(allowlist.Table)
	columns := alq.ctx.Fields
	if len(columns) == 0 {
		columns = allowlist.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if alq.sql != nil {
		selector = alq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if alq.ctx.Unique != nil && *alq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range alq.predicates {
		p(selector)
	}
	for _, p := range alq.order {
		p(selector)
	}
	if offset := alq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := alq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// AllowListGroupBy is the group-by builder for AllowList entities.
type AllowListGroupBy struct {
	selector
	build *AllowListQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (algb *AllowListGroupBy) Aggregate(fns ...AggregateFunc) *AllowListGroupBy {
	algb.fns = append(algb.fns, fns...)
	return algb
}

// Scan applies the selector query and scans the result into the given value.
func (algb *AllowListGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, algb.build.ctx, "GroupBy")
	if err := algb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*AllowListQuery, *AllowListGroupBy](ctx, algb.build, algb, algb.build.inters, v)
}

func (algb *AllowListGroupBy) sqlScan(ctx context.Context, root *AllowListQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(algb.fns))
	for _, fn := range algb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*algb.flds)+len(algb.fns))
		for _, f := range *algb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*algb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := algb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// AllowListSelect is the builder for selecting fields of AllowList entities.
type AllowListSelect struct {
	*AllowListQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (als *AllowListSelect) Aggregate(fns ...AggregateFunc) *AllowListSelect {
	als.fns = append(als.fns, fns...)
	return als
}

// Scan applies the selector query and scans the result into the given value.
func (als *AllowListSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, als.ctx, "Select")
	if err := als.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*AllowListQuery, *AllowListSelect](ctx, als.AllowListQuery, als, als.inters, v)
}

func (als *AllowListSelect) sqlScan(ctx context.Context, root *AllowListQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(als.fns))
	for _, fn := range als.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*als.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := als.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
