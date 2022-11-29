// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent/migrate"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/bouncer"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/event"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/meta"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

// Client is the client that holds all ent builders.
type Client struct {
	config
	// Schema is the client for creating, migrating and dropping schema.
	Schema *migrate.Schema
	// Alert is the client for interacting with the Alert builders.
	Alert *AlertClient
	// Bouncer is the client for interacting with the Bouncer builders.
	Bouncer *BouncerClient
	// Decision is the client for interacting with the Decision builders.
	Decision *DecisionClient
	// Event is the client for interacting with the Event builders.
	Event *EventClient
	// Machine is the client for interacting with the Machine builders.
	Machine *MachineClient
	// Meta is the client for interacting with the Meta builders.
	Meta *MetaClient
}

// NewClient creates a new client configured with the given options.
func NewClient(opts ...Option) *Client {
	cfg := config{log: log.Println, hooks: &hooks{}}
	cfg.options(opts...)
	client := &Client{config: cfg}
	client.init()
	return client
}

func (c *Client) init() {
	c.Schema = migrate.NewSchema(c.driver)
	c.Alert = NewAlertClient(c.config)
	c.Bouncer = NewBouncerClient(c.config)
	c.Decision = NewDecisionClient(c.config)
	c.Event = NewEventClient(c.config)
	c.Machine = NewMachineClient(c.config)
	c.Meta = NewMetaClient(c.config)
}

// Open opens a database/sql.DB specified by the driver name and
// the data source name, and returns a new client attached to it.
// Optional parameters can be added for configuring the client.
func Open(driverName, dataSourceName string, options ...Option) (*Client, error) {
	switch driverName {
	case dialect.MySQL, dialect.Postgres, dialect.SQLite:
		drv, err := sql.Open(driverName, dataSourceName)
		if err != nil {
			return nil, err
		}
		return NewClient(append(options, Driver(drv))...), nil
	default:
		return nil, fmt.Errorf("unsupported driver: %q", driverName)
	}
}

// Tx returns a new transactional client. The provided context
// is used until the transaction is committed or rolled back.
func (c *Client) Tx(ctx context.Context) (*Tx, error) {
	if _, ok := c.driver.(*txDriver); ok {
		return nil, errors.New("ent: cannot start a transaction within a transaction")
	}
	tx, err := newTx(ctx, c.driver)
	if err != nil {
		return nil, fmt.Errorf("ent: starting a transaction: %w", err)
	}
	cfg := c.config
	cfg.driver = tx
	return &Tx{
		ctx:      ctx,
		config:   cfg,
		Alert:    NewAlertClient(cfg),
		Bouncer:  NewBouncerClient(cfg),
		Decision: NewDecisionClient(cfg),
		Event:    NewEventClient(cfg),
		Machine:  NewMachineClient(cfg),
		Meta:     NewMetaClient(cfg),
	}, nil
}

// BeginTx returns a transactional client with specified options.
func (c *Client) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	if _, ok := c.driver.(*txDriver); ok {
		return nil, errors.New("ent: cannot start a transaction within a transaction")
	}
	tx, err := c.driver.(interface {
		BeginTx(context.Context, *sql.TxOptions) (dialect.Tx, error)
	}).BeginTx(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("ent: starting a transaction: %w", err)
	}
	cfg := c.config
	cfg.driver = &txDriver{tx: tx, drv: c.driver}
	return &Tx{
		ctx:      ctx,
		config:   cfg,
		Alert:    NewAlertClient(cfg),
		Bouncer:  NewBouncerClient(cfg),
		Decision: NewDecisionClient(cfg),
		Event:    NewEventClient(cfg),
		Machine:  NewMachineClient(cfg),
		Meta:     NewMetaClient(cfg),
	}, nil
}

// Debug returns a new debug-client. It's used to get verbose logging on specific operations.
//
//	client.Debug().
//		Alert.
//		Query().
//		Count(ctx)
func (c *Client) Debug() *Client {
	if c.debug {
		return c
	}
	cfg := c.config
	cfg.driver = dialect.Debug(c.driver, c.log)
	client := &Client{config: cfg}
	client.init()
	return client
}

// Close closes the database connection and prevents new queries from starting.
func (c *Client) Close() error {
	return c.driver.Close()
}

// Use adds the mutation hooks to all the entity clients.
// In order to add hooks to a specific client, call: `client.Node.Use(...)`.
func (c *Client) Use(hooks ...Hook) {
	c.Alert.Use(hooks...)
	c.Bouncer.Use(hooks...)
	c.Decision.Use(hooks...)
	c.Event.Use(hooks...)
	c.Machine.Use(hooks...)
	c.Meta.Use(hooks...)
}

// AlertClient is a client for the Alert schema.
type AlertClient struct {
	config
}

// NewAlertClient returns a client for the Alert from the given config.
func NewAlertClient(c config) *AlertClient {
	return &AlertClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `alert.Hooks(f(g(h())))`.
func (c *AlertClient) Use(hooks ...Hook) {
	c.hooks.Alert = append(c.hooks.Alert, hooks...)
}

// Create returns a builder for creating a Alert entity.
func (c *AlertClient) Create() *AlertCreate {
	mutation := newAlertMutation(c.config, OpCreate)
	return &AlertCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Alert entities.
func (c *AlertClient) CreateBulk(builders ...*AlertCreate) *AlertCreateBulk {
	return &AlertCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Alert.
func (c *AlertClient) Update() *AlertUpdate {
	mutation := newAlertMutation(c.config, OpUpdate)
	return &AlertUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *AlertClient) UpdateOne(a *Alert) *AlertUpdateOne {
	mutation := newAlertMutation(c.config, OpUpdateOne, withAlert(a))
	return &AlertUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *AlertClient) UpdateOneID(id int) *AlertUpdateOne {
	mutation := newAlertMutation(c.config, OpUpdateOne, withAlertID(id))
	return &AlertUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Alert.
func (c *AlertClient) Delete() *AlertDelete {
	mutation := newAlertMutation(c.config, OpDelete)
	return &AlertDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *AlertClient) DeleteOne(a *Alert) *AlertDeleteOne {
	return c.DeleteOneID(a.ID)
}

// DeleteOne returns a builder for deleting the given entity by its id.
func (c *AlertClient) DeleteOneID(id int) *AlertDeleteOne {
	builder := c.Delete().Where(alert.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &AlertDeleteOne{builder}
}

// Query returns a query builder for Alert.
func (c *AlertClient) Query() *AlertQuery {
	return &AlertQuery{
		config: c.config,
	}
}

// Get returns a Alert entity by its id.
func (c *AlertClient) Get(ctx context.Context, id int) (*Alert, error) {
	return c.Query().Where(alert.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *AlertClient) GetX(ctx context.Context, id int) *Alert {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryOwner queries the owner edge of a Alert.
func (c *AlertClient) QueryOwner(a *Alert) *MachineQuery {
	query := &MachineQuery{config: c.config}
	query.path = func(ctx context.Context) (fromV *sql.Selector, _ error) {
		id := a.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(alert.Table, alert.FieldID, id),
			sqlgraph.To(machine.Table, machine.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, alert.OwnerTable, alert.OwnerColumn),
		)
		fromV = sqlgraph.Neighbors(a.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// QueryDecisions queries the decisions edge of a Alert.
func (c *AlertClient) QueryDecisions(a *Alert) *DecisionQuery {
	query := &DecisionQuery{config: c.config}
	query.path = func(ctx context.Context) (fromV *sql.Selector, _ error) {
		id := a.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(alert.Table, alert.FieldID, id),
			sqlgraph.To(decision.Table, decision.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, alert.DecisionsTable, alert.DecisionsColumn),
		)
		fromV = sqlgraph.Neighbors(a.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// QueryEvents queries the events edge of a Alert.
func (c *AlertClient) QueryEvents(a *Alert) *EventQuery {
	query := &EventQuery{config: c.config}
	query.path = func(ctx context.Context) (fromV *sql.Selector, _ error) {
		id := a.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(alert.Table, alert.FieldID, id),
			sqlgraph.To(event.Table, event.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, alert.EventsTable, alert.EventsColumn),
		)
		fromV = sqlgraph.Neighbors(a.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// QueryMetas queries the metas edge of a Alert.
func (c *AlertClient) QueryMetas(a *Alert) *MetaQuery {
	query := &MetaQuery{config: c.config}
	query.path = func(ctx context.Context) (fromV *sql.Selector, _ error) {
		id := a.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(alert.Table, alert.FieldID, id),
			sqlgraph.To(meta.Table, meta.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, alert.MetasTable, alert.MetasColumn),
		)
		fromV = sqlgraph.Neighbors(a.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *AlertClient) Hooks() []Hook {
	return c.hooks.Alert
}

// BouncerClient is a client for the Bouncer schema.
type BouncerClient struct {
	config
}

// NewBouncerClient returns a client for the Bouncer from the given config.
func NewBouncerClient(c config) *BouncerClient {
	return &BouncerClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `bouncer.Hooks(f(g(h())))`.
func (c *BouncerClient) Use(hooks ...Hook) {
	c.hooks.Bouncer = append(c.hooks.Bouncer, hooks...)
}

// Create returns a builder for creating a Bouncer entity.
func (c *BouncerClient) Create() *BouncerCreate {
	mutation := newBouncerMutation(c.config, OpCreate)
	return &BouncerCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Bouncer entities.
func (c *BouncerClient) CreateBulk(builders ...*BouncerCreate) *BouncerCreateBulk {
	return &BouncerCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Bouncer.
func (c *BouncerClient) Update() *BouncerUpdate {
	mutation := newBouncerMutation(c.config, OpUpdate)
	return &BouncerUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *BouncerClient) UpdateOne(b *Bouncer) *BouncerUpdateOne {
	mutation := newBouncerMutation(c.config, OpUpdateOne, withBouncer(b))
	return &BouncerUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *BouncerClient) UpdateOneID(id int) *BouncerUpdateOne {
	mutation := newBouncerMutation(c.config, OpUpdateOne, withBouncerID(id))
	return &BouncerUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Bouncer.
func (c *BouncerClient) Delete() *BouncerDelete {
	mutation := newBouncerMutation(c.config, OpDelete)
	return &BouncerDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *BouncerClient) DeleteOne(b *Bouncer) *BouncerDeleteOne {
	return c.DeleteOneID(b.ID)
}

// DeleteOne returns a builder for deleting the given entity by its id.
func (c *BouncerClient) DeleteOneID(id int) *BouncerDeleteOne {
	builder := c.Delete().Where(bouncer.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &BouncerDeleteOne{builder}
}

// Query returns a query builder for Bouncer.
func (c *BouncerClient) Query() *BouncerQuery {
	return &BouncerQuery{
		config: c.config,
	}
}

// Get returns a Bouncer entity by its id.
func (c *BouncerClient) Get(ctx context.Context, id int) (*Bouncer, error) {
	return c.Query().Where(bouncer.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *BouncerClient) GetX(ctx context.Context, id int) *Bouncer {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// Hooks returns the client hooks.
func (c *BouncerClient) Hooks() []Hook {
	return c.hooks.Bouncer
}

// DecisionClient is a client for the Decision schema.
type DecisionClient struct {
	config
}

// NewDecisionClient returns a client for the Decision from the given config.
func NewDecisionClient(c config) *DecisionClient {
	return &DecisionClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `decision.Hooks(f(g(h())))`.
func (c *DecisionClient) Use(hooks ...Hook) {
	c.hooks.Decision = append(c.hooks.Decision, hooks...)
}

// Create returns a builder for creating a Decision entity.
func (c *DecisionClient) Create() *DecisionCreate {
	mutation := newDecisionMutation(c.config, OpCreate)
	return &DecisionCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Decision entities.
func (c *DecisionClient) CreateBulk(builders ...*DecisionCreate) *DecisionCreateBulk {
	return &DecisionCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Decision.
func (c *DecisionClient) Update() *DecisionUpdate {
	mutation := newDecisionMutation(c.config, OpUpdate)
	return &DecisionUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *DecisionClient) UpdateOne(d *Decision) *DecisionUpdateOne {
	mutation := newDecisionMutation(c.config, OpUpdateOne, withDecision(d))
	return &DecisionUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *DecisionClient) UpdateOneID(id int) *DecisionUpdateOne {
	mutation := newDecisionMutation(c.config, OpUpdateOne, withDecisionID(id))
	return &DecisionUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Decision.
func (c *DecisionClient) Delete() *DecisionDelete {
	mutation := newDecisionMutation(c.config, OpDelete)
	return &DecisionDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *DecisionClient) DeleteOne(d *Decision) *DecisionDeleteOne {
	return c.DeleteOneID(d.ID)
}

// DeleteOne returns a builder for deleting the given entity by its id.
func (c *DecisionClient) DeleteOneID(id int) *DecisionDeleteOne {
	builder := c.Delete().Where(decision.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &DecisionDeleteOne{builder}
}

// Query returns a query builder for Decision.
func (c *DecisionClient) Query() *DecisionQuery {
	return &DecisionQuery{
		config: c.config,
	}
}

// Get returns a Decision entity by its id.
func (c *DecisionClient) Get(ctx context.Context, id int) (*Decision, error) {
	return c.Query().Where(decision.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *DecisionClient) GetX(ctx context.Context, id int) *Decision {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryOwner queries the owner edge of a Decision.
func (c *DecisionClient) QueryOwner(d *Decision) *AlertQuery {
	query := &AlertQuery{config: c.config}
	query.path = func(ctx context.Context) (fromV *sql.Selector, _ error) {
		id := d.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(decision.Table, decision.FieldID, id),
			sqlgraph.To(alert.Table, alert.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, decision.OwnerTable, decision.OwnerColumn),
		)
		fromV = sqlgraph.Neighbors(d.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *DecisionClient) Hooks() []Hook {
	return c.hooks.Decision
}

// EventClient is a client for the Event schema.
type EventClient struct {
	config
}

// NewEventClient returns a client for the Event from the given config.
func NewEventClient(c config) *EventClient {
	return &EventClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `event.Hooks(f(g(h())))`.
func (c *EventClient) Use(hooks ...Hook) {
	c.hooks.Event = append(c.hooks.Event, hooks...)
}

// Create returns a builder for creating a Event entity.
func (c *EventClient) Create() *EventCreate {
	mutation := newEventMutation(c.config, OpCreate)
	return &EventCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Event entities.
func (c *EventClient) CreateBulk(builders ...*EventCreate) *EventCreateBulk {
	return &EventCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Event.
func (c *EventClient) Update() *EventUpdate {
	mutation := newEventMutation(c.config, OpUpdate)
	return &EventUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *EventClient) UpdateOne(e *Event) *EventUpdateOne {
	mutation := newEventMutation(c.config, OpUpdateOne, withEvent(e))
	return &EventUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *EventClient) UpdateOneID(id int) *EventUpdateOne {
	mutation := newEventMutation(c.config, OpUpdateOne, withEventID(id))
	return &EventUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Event.
func (c *EventClient) Delete() *EventDelete {
	mutation := newEventMutation(c.config, OpDelete)
	return &EventDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *EventClient) DeleteOne(e *Event) *EventDeleteOne {
	return c.DeleteOneID(e.ID)
}

// DeleteOne returns a builder for deleting the given entity by its id.
func (c *EventClient) DeleteOneID(id int) *EventDeleteOne {
	builder := c.Delete().Where(event.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &EventDeleteOne{builder}
}

// Query returns a query builder for Event.
func (c *EventClient) Query() *EventQuery {
	return &EventQuery{
		config: c.config,
	}
}

// Get returns a Event entity by its id.
func (c *EventClient) Get(ctx context.Context, id int) (*Event, error) {
	return c.Query().Where(event.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *EventClient) GetX(ctx context.Context, id int) *Event {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryOwner queries the owner edge of a Event.
func (c *EventClient) QueryOwner(e *Event) *AlertQuery {
	query := &AlertQuery{config: c.config}
	query.path = func(ctx context.Context) (fromV *sql.Selector, _ error) {
		id := e.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(event.Table, event.FieldID, id),
			sqlgraph.To(alert.Table, alert.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, event.OwnerTable, event.OwnerColumn),
		)
		fromV = sqlgraph.Neighbors(e.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *EventClient) Hooks() []Hook {
	return c.hooks.Event
}

// MachineClient is a client for the Machine schema.
type MachineClient struct {
	config
}

// NewMachineClient returns a client for the Machine from the given config.
func NewMachineClient(c config) *MachineClient {
	return &MachineClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `machine.Hooks(f(g(h())))`.
func (c *MachineClient) Use(hooks ...Hook) {
	c.hooks.Machine = append(c.hooks.Machine, hooks...)
}

// Create returns a builder for creating a Machine entity.
func (c *MachineClient) Create() *MachineCreate {
	mutation := newMachineMutation(c.config, OpCreate)
	return &MachineCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Machine entities.
func (c *MachineClient) CreateBulk(builders ...*MachineCreate) *MachineCreateBulk {
	return &MachineCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Machine.
func (c *MachineClient) Update() *MachineUpdate {
	mutation := newMachineMutation(c.config, OpUpdate)
	return &MachineUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *MachineClient) UpdateOne(m *Machine) *MachineUpdateOne {
	mutation := newMachineMutation(c.config, OpUpdateOne, withMachine(m))
	return &MachineUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *MachineClient) UpdateOneID(id int) *MachineUpdateOne {
	mutation := newMachineMutation(c.config, OpUpdateOne, withMachineID(id))
	return &MachineUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Machine.
func (c *MachineClient) Delete() *MachineDelete {
	mutation := newMachineMutation(c.config, OpDelete)
	return &MachineDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *MachineClient) DeleteOne(m *Machine) *MachineDeleteOne {
	return c.DeleteOneID(m.ID)
}

// DeleteOne returns a builder for deleting the given entity by its id.
func (c *MachineClient) DeleteOneID(id int) *MachineDeleteOne {
	builder := c.Delete().Where(machine.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &MachineDeleteOne{builder}
}

// Query returns a query builder for Machine.
func (c *MachineClient) Query() *MachineQuery {
	return &MachineQuery{
		config: c.config,
	}
}

// Get returns a Machine entity by its id.
func (c *MachineClient) Get(ctx context.Context, id int) (*Machine, error) {
	return c.Query().Where(machine.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *MachineClient) GetX(ctx context.Context, id int) *Machine {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryAlerts queries the alerts edge of a Machine.
func (c *MachineClient) QueryAlerts(m *Machine) *AlertQuery {
	query := &AlertQuery{config: c.config}
	query.path = func(ctx context.Context) (fromV *sql.Selector, _ error) {
		id := m.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(machine.Table, machine.FieldID, id),
			sqlgraph.To(alert.Table, alert.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, machine.AlertsTable, machine.AlertsColumn),
		)
		fromV = sqlgraph.Neighbors(m.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *MachineClient) Hooks() []Hook {
	return c.hooks.Machine
}

// MetaClient is a client for the Meta schema.
type MetaClient struct {
	config
}

// NewMetaClient returns a client for the Meta from the given config.
func NewMetaClient(c config) *MetaClient {
	return &MetaClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `meta.Hooks(f(g(h())))`.
func (c *MetaClient) Use(hooks ...Hook) {
	c.hooks.Meta = append(c.hooks.Meta, hooks...)
}

// Create returns a builder for creating a Meta entity.
func (c *MetaClient) Create() *MetaCreate {
	mutation := newMetaMutation(c.config, OpCreate)
	return &MetaCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Meta entities.
func (c *MetaClient) CreateBulk(builders ...*MetaCreate) *MetaCreateBulk {
	return &MetaCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Meta.
func (c *MetaClient) Update() *MetaUpdate {
	mutation := newMetaMutation(c.config, OpUpdate)
	return &MetaUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *MetaClient) UpdateOne(m *Meta) *MetaUpdateOne {
	mutation := newMetaMutation(c.config, OpUpdateOne, withMeta(m))
	return &MetaUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *MetaClient) UpdateOneID(id int) *MetaUpdateOne {
	mutation := newMetaMutation(c.config, OpUpdateOne, withMetaID(id))
	return &MetaUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Meta.
func (c *MetaClient) Delete() *MetaDelete {
	mutation := newMetaMutation(c.config, OpDelete)
	return &MetaDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *MetaClient) DeleteOne(m *Meta) *MetaDeleteOne {
	return c.DeleteOneID(m.ID)
}

// DeleteOne returns a builder for deleting the given entity by its id.
func (c *MetaClient) DeleteOneID(id int) *MetaDeleteOne {
	builder := c.Delete().Where(meta.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &MetaDeleteOne{builder}
}

// Query returns a query builder for Meta.
func (c *MetaClient) Query() *MetaQuery {
	return &MetaQuery{
		config: c.config,
	}
}

// Get returns a Meta entity by its id.
func (c *MetaClient) Get(ctx context.Context, id int) (*Meta, error) {
	return c.Query().Where(meta.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *MetaClient) GetX(ctx context.Context, id int) *Meta {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryOwner queries the owner edge of a Meta.
func (c *MetaClient) QueryOwner(m *Meta) *AlertQuery {
	query := &AlertQuery{config: c.config}
	query.path = func(ctx context.Context) (fromV *sql.Selector, _ error) {
		id := m.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(meta.Table, meta.FieldID, id),
			sqlgraph.To(alert.Table, alert.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, meta.OwnerTable, meta.OwnerColumn),
		)
		fromV = sqlgraph.Neighbors(m.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *MetaClient) Hooks() []Hook {
	return c.hooks.Meta
}
