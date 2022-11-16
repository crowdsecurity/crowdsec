// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"ariga.io/atlas/sql/schema"
)

type (
	// A Plan defines a planned changeset that its execution brings the database to
	// the new desired state. Additional information is calculated by the different
	// drivers to indicate if the changeset is transactional (can be rolled-back) and
	// reversible (a down file can be generated to it).
	Plan struct {
		// Version and Name of the plan. Provided by the user or auto-generated.
		Version, Name string

		// Reversible describes if the changeset is reversible.
		Reversible bool

		// Transactional describes if the changeset is transactional.
		Transactional bool

		// Changes defines the list of changeset in the plan.
		Changes []*Change
	}

	// A Change of migration.
	Change struct {
		// Cmd or statement to execute.
		Cmd string

		// Args for placeholder parameters in the statement above.
		Args []any

		// A Comment describes the change.
		Comment string

		// Reverse contains the "reversed statement" if
		// command is reversible.
		Reverse string

		// The Source that caused this change, or nil.
		Source schema.Change
	}
)

type (
	// The Driver interface must be implemented by the different dialects to support database
	// migration authoring/planning and applying. ExecQuerier, Inspector and Differ, provide
	// basic schema primitives for inspecting database schemas, calculate the difference between
	// schema elements, and executing raw SQL statements. The PlanApplier interface wraps the
	// methods for generating migration plan for applying the actual changes on the database.
	Driver interface {
		schema.Differ
		schema.ExecQuerier
		schema.Inspector
		PlanApplier
	}

	// PlanApplier wraps the methods for planning and applying changes
	// on the database.
	PlanApplier interface {
		// PlanChanges returns a migration plan for applying the given changeset.
		PlanChanges(context.Context, string, []schema.Change, ...PlanOption) (*Plan, error)

		// ApplyChanges is responsible for applying the given changeset.
		// An error may return from ApplyChanges if the driver is unable
		// to execute a change.
		ApplyChanges(context.Context, []schema.Change, ...PlanOption) error
	}

	// PlanOptions holds the migration plan options to be used by PlanApplier.
	PlanOptions struct {
		// PlanWithSchemaQualifier allows setting a custom schema to prefix
		// tables and other resources. An empty string indicates no qualifier.
		SchemaQualifier *string
	}

	// PlanOption allows configuring a drivers' plan using functional arguments.
	PlanOption func(*PlanOptions)

	// StateReader wraps the method for reading a database/schema state.
	// The types below provides a few builtin options for reading a state
	// from a migration directory, a static object (e.g. a parsed file).
	StateReader interface {
		ReadState(ctx context.Context) (*schema.Realm, error)
	}

	// The StateReaderFunc type is an adapter to allow the use of
	// ordinary functions as state readers.
	StateReaderFunc func(ctx context.Context) (*schema.Realm, error)
)

// ReadState calls f(ctx).
func (f StateReaderFunc) ReadState(ctx context.Context) (*schema.Realm, error) {
	return f(ctx)
}

// ErrNoPlan is returned by Plan when there is no change between the two states.
var ErrNoPlan = errors.New("sql/migrate: no plan for matched states")

// Realm returns a StateReader for the static Realm object.
func Realm(r *schema.Realm) StateReader {
	return StateReaderFunc(func(context.Context) (*schema.Realm, error) {
		return r, nil
	})
}

// Schema returns a StateReader for the static Schema object.
func Schema(s *schema.Schema) StateReader {
	return StateReaderFunc(func(context.Context) (*schema.Realm, error) {
		r := &schema.Realm{Schemas: []*schema.Schema{s}}
		if s.Realm != nil {
			r.Attrs = s.Realm.Attrs
		}
		s.Realm = r
		return r, nil
	})
}

// RealmConn returns a StateReader for a Driver connected to a database.
func RealmConn(drv Driver, opts *schema.InspectRealmOption) StateReader {
	return StateReaderFunc(func(ctx context.Context) (*schema.Realm, error) {
		return drv.InspectRealm(ctx, opts)
	})
}

// SchemaConn returns a StateReader for a Driver connected to a schema.
func SchemaConn(drv Driver, name string, opts *schema.InspectOptions) StateReader {
	return StateReaderFunc(func(ctx context.Context) (*schema.Realm, error) {
		s, err := drv.InspectSchema(ctx, name, opts)
		if err != nil {
			return nil, err
		}
		return Schema(s).ReadState(ctx)
	})
}

type (
	// Planner can plan the steps to take to migrate from one state to another. It uses the enclosed Dir to write
	// those changes to versioned migration files.
	Planner struct {
		drv  Driver       // driver to use
		dir  Dir          // where migration files are stored and read from
		fmt  Formatter    // how to format a plan to migration files
		sum  bool         // whether to create a sum file for the migration directory
		opts []PlanOption // driver options
	}

	// PlannerOption allows managing a Planner using functional arguments.
	PlannerOption func(*Planner)

	// A RevisionReadWriter wraps the functionality for reading and writing migration revisions in a database table.
	RevisionReadWriter interface {
		// Ident returns an object identifies this history table.
		Ident() *TableIdent
		// ReadRevisions returns all revisions.
		ReadRevisions(context.Context) ([]*Revision, error)
		// ReadRevision returns a revision by version.
		// Returns ErrRevisionNotExist if the version does not exist.
		ReadRevision(context.Context, string) (*Revision, error)
		// WriteRevision saves the revision to the storage.
		WriteRevision(context.Context, *Revision) error
		// DeleteRevision deletes a revision by version from the storage.
		DeleteRevision(context.Context, string) error
	}

	// A Revision denotes an applied migration in a deployment. Used to track migration executions state of a database.
	Revision struct {
		// Version of the migration.
		Version string
		// Description of this migration.
		Description string
		// Type of the migration.
		Type RevisionType
		// Applied denotes the amount of successfully applied statements of the revision.
		Applied int
		// Total denotes the total amount of statements of the migration.
		Total int
		// ExecutedAt denotes when this migration was started to be executed.
		ExecutedAt time.Time
		// ExecutionTime denotes the time it took for this migration to be applied on the database.
		ExecutionTime time.Duration
		// Error holds information about a migration error (if occurred).
		// If the error is from the application level, it is prefixed with "Go:\n".
		// If the error is raised from the database, Error contains both the failed statement and the database error
		// following the "SQL:\n<sql>\n\nError:\n<err>" format.
		Error string
		// Hash is the check-sum of this migration as stated by the migration directories HashFile.
		Hash string
		// PartialHashes contains one hash per statement that has been applied on the database.
		PartialHashes []string
		// OperatorVersion holds a string representation of the Atlas operator managing this database migration.
		OperatorVersion string
	}

	// RevisionType defines the type of the revision record in the history table.
	RevisionType uint

	// Executor is responsible to manage and execute a set of migration files against a database.
	Executor struct {
		drv         Driver             // The Driver to access and manage the database.
		dir         Dir                // The Dir with migration files to use.
		rrw         RevisionReadWriter // The RevisionReadWriter to read and write database revisions to.
		log         Logger             // The Logger to use.
		fromVer     string             // Calculate pending files from the given version (including it).
		baselineVer string             // Start the first migration after the given baseline version.
		allowDirty  bool               // Allow start working on a non-clean database.
		operator    string             // Revision.OperatorVersion
	}

	// ExecutorOption allows configuring an Executor using functional arguments.
	ExecutorOption func(*Executor) error
)

const (
	// RevisionTypeUnknown represents an unknown revision type.
	// This type is unexpected and exists here to only ensure
	// the type is not set to the zero value.
	RevisionTypeUnknown RevisionType = 0

	// RevisionTypeBaseline represents a baseline revision. Note that only
	// the first record can represent a baseline migration and most of its
	// fields are set to the zero value.
	RevisionTypeBaseline RevisionType = 1 << (iota - 1)

	// RevisionTypeExecute represents a migration that was executed.
	RevisionTypeExecute

	// RevisionTypeResolved represents a migration that was resolved. A migration
	// script that was script executed and then resolved should set its Type to
	// RevisionTypeExecute | RevisionTypeResolved.
	RevisionTypeResolved
)

// NewPlanner creates a new Planner.
func NewPlanner(drv Driver, dir Dir, opts ...PlannerOption) *Planner {
	p := &Planner{drv: drv, dir: dir, sum: true}
	for _, opt := range opts {
		opt(p)
	}
	if p.fmt == nil {
		p.fmt = DefaultFormatter
	}
	return p
}

// PlanWithSchemaQualifier allows setting a custom schema to prefix tables and
// other resources. An empty string indicates no prefix.
//
// Note, this options require the changes to be scoped to one
// schema and returns an error otherwise.
func PlanWithSchemaQualifier(q string) PlannerOption {
	return func(p *Planner) {
		p.opts = append(p.opts, func(o *PlanOptions) {
			o.SchemaQualifier = &q
		})
	}
}

// PlanFormat sets the Formatter of a Planner.
func PlanFormat(fmt Formatter) PlannerOption {
	return func(p *Planner) {
		p.fmt = fmt
	}
}

// PlanWithChecksum allows setting if the hash-sum functionality
// for the migration directory is enabled or not.
func PlanWithChecksum(b bool) PlannerOption {
	return func(p *Planner) {
		p.sum = b
	}
}

var (
	// WithFormatter calls PlanFormat.
	// Deprecated: use PlanFormat instead.
	WithFormatter = PlanFormat
	// DisableChecksum calls PlanWithChecksum(false).
	// Deprecated: use PlanWithoutChecksum instead.
	DisableChecksum = func() PlannerOption { return PlanWithChecksum(false) }
)

// Plan calculates the migration Plan required for moving the current state (from) state to
// the next state (to). A StateReader can be a directory, static schema elements or a Driver connection.
func (p *Planner) Plan(ctx context.Context, name string, to StateReader) (*Plan, error) {
	return p.plan(ctx, name, to, true)
}

// PlanSchema is like Plan but limits its scope to the schema connection.
// Note, the operation fails in case the connection was not set to a schema.
func (p *Planner) PlanSchema(ctx context.Context, name string, to StateReader) (*Plan, error) {
	return p.plan(ctx, name, to, false)
}

func (p *Planner) plan(ctx context.Context, name string, to StateReader, realmScope bool) (*Plan, error) {
	from, err := NewExecutor(p.drv, p.dir, NopRevisionReadWriter{})
	if err != nil {
		return nil, err
	}
	current, err := from.Replay(ctx, func() StateReader {
		if realmScope {
			return RealmConn(p.drv, nil)
		}
		// In case the scope is the schema connection,
		// inspect it and return its connected realm.
		return SchemaConn(p.drv, "", nil)
	}())
	if err != nil {
		return nil, err
	}
	desired, err := to.ReadState(ctx)
	if err != nil {
		return nil, err
	}
	var changes []schema.Change
	switch {
	case realmScope:
		changes, err = p.drv.RealmDiff(current, desired)
	default:
		switch n, m := len(current.Schemas), len(desired.Schemas); {
		case n == 0:
			return nil, errors.New("no schema was found in current state after replaying migration directory")
		case n > 1:
			return nil, fmt.Errorf("%d schemas were found in current state after replaying migration directory", len(current.Schemas))
		case m == 0:
			return nil, errors.New("no schema was found in desired state")
		case m > 1:
			return nil, fmt.Errorf("%d schemas were found in desired state; expect 1", len(desired.Schemas))
		default:
			s1, s2 := *current.Schemas[0], *desired.Schemas[0]
			// Avoid comparing schema names when scope is limited to one schema,
			// and the schema qualifier is controlled by the caller.
			if s1.Name != s2.Name {
				s1.Name = s2.Name
			}
			changes, err = p.drv.SchemaDiff(&s1, &s2)
		}
	}
	if err != nil {
		return nil, err
	}
	if len(changes) == 0 {
		return nil, ErrNoPlan
	}
	return p.drv.PlanChanges(ctx, name, changes, p.opts...)
}

// WritePlan writes the given Plan to the Dir based on the configured Formatter.
func (p *Planner) WritePlan(plan *Plan) error {
	// Format the plan into files.
	files, err := p.fmt.Format(plan)
	if err != nil {
		return err
	}
	// Store the files in the migration directory.
	for _, f := range files {
		if err := p.dir.WriteFile(f.Name(), f.Bytes()); err != nil {
			return err
		}
	}
	// If enabled, update the sum file.
	if p.sum {
		sum, err := p.dir.Checksum()
		if err != nil {
			return err
		}
		return WriteSumFile(p.dir, sum)
	}
	return nil
}

var (
	// ErrNoPendingFiles is returned if there are no pending migration files to execute on the managed database.
	ErrNoPendingFiles = errors.New("sql/migrate: execute: nothing to do")
	// ErrSnapshotUnsupported is returned if there is no Snapshoter given.
	ErrSnapshotUnsupported = errors.New("sql/migrate: driver does not support taking a database snapshot")
	// ErrCleanCheckerUnsupported is returned if there is no CleanChecker given.
	ErrCleanCheckerUnsupported = errors.New("sql/migrate: driver does not support checking if database is clean")
	// ErrRevisionNotExist is returned if the requested revision is not found in the storage.
	ErrRevisionNotExist = errors.New("sql/migrate: revision not found")
)

// MissingMigrationError is returned if a revision is partially applied but
// the matching migration file is not found in the migration directory.
type MissingMigrationError struct{ Version, Description string }

// Error implements error.
func (e MissingMigrationError) Error() string {
	return fmt.Sprintf(
		"sql/migrate: missing migration: revision %q is partially applied but migration file was not found",
		fmt.Sprintf("%s_%s.sql", e.Version, e.Description),
	)
}

// NewExecutor creates a new Executor with default values.
func NewExecutor(drv Driver, dir Dir, rrw RevisionReadWriter, opts ...ExecutorOption) (*Executor, error) {
	if drv == nil {
		return nil, errors.New("sql/migrate: execute: no driver given")
	}
	if dir == nil {
		return nil, errors.New("sql/migrate: execute: no dir given")
	}
	if rrw == nil {
		return nil, errors.New("sql/migrate: execute: no revision storage given")
	}
	ex := &Executor{drv: drv, dir: dir, rrw: rrw}
	for _, opt := range opts {
		if err := opt(ex); err != nil {
			return nil, err
		}
	}
	if ex.log == nil {
		ex.log = NopLogger{}
	}
	if _, ok := drv.(Snapshoter); !ok {
		return nil, ErrSnapshotUnsupported
	}
	if _, ok := drv.(CleanChecker); !ok {
		return nil, ErrCleanCheckerUnsupported
	}
	if ex.baselineVer != "" && ex.allowDirty {
		return nil, errors.New("sql/migrate: execute: baseline and allow-dirty are mutually exclusive")
	}
	return ex, nil
}

// WithAllowDirty defines if we can start working on a non-clean database
// in the first migration execution.
func WithAllowDirty(b bool) ExecutorOption {
	return func(ex *Executor) error {
		ex.allowDirty = b
		return nil
	}
}

// WithBaselineVersion allows setting the baseline version of the database on the
// first migration. Hence, all versions up to and including this version are skipped.
func WithBaselineVersion(v string) ExecutorOption {
	return func(ex *Executor) error {
		ex.baselineVer = v
		return nil
	}
}

// WithLogger sets the Logger of an Executor.
func WithLogger(log Logger) ExecutorOption {
	return func(ex *Executor) error {
		ex.log = log
		return nil
	}
}

// WithFromVersion allows passing a file version as a starting point for calculating
// pending migration scripts. It can be useful for skipping specific files.
func WithFromVersion(v string) ExecutorOption {
	return func(ex *Executor) error {
		ex.fromVer = v
		return nil
	}
}

// WithOperatorVersion sets the operator version to save on the revisions
// when executing migration files.
func WithOperatorVersion(v string) ExecutorOption {
	return func(ex *Executor) error {
		ex.operator = v
		return nil
	}
}

// Pending returns all pending (not fully applied) migration files in the migration directory.
func (e *Executor) Pending(ctx context.Context) ([]File, error) {
	// Don't operate with a broken migration directory.
	if err := Validate(e.dir); err != nil {
		return nil, fmt.Errorf("sql/migrate: execute: validate migration directory: %w", err)
	}
	// Read all applied database revisions.
	revs, err := e.rrw.ReadRevisions(ctx)
	if err != nil {
		return nil, fmt.Errorf("sql/migrate: execute: read revisions: %w", err)
	}
	// Select the correct migration files.
	migrations, err := e.dir.Files()
	if err != nil {
		return nil, fmt.Errorf("sql/migrate: execute: select migration files: %w", err)
	}
	if len(migrations) == 0 {
		return nil, ErrNoPendingFiles
	}
	var pending []File
	switch {
	// If it is the first time we run.
	case len(revs) == 0:
		var cerr *NotCleanError
		if err = e.drv.(CleanChecker).CheckClean(ctx, e.rrw.Ident()); err != nil && !errors.As(err, &cerr) {
			return nil, err
		}
		// In case the workspace is not clean one of the flags is required.
		if cerr != nil && !e.allowDirty && e.baselineVer == "" {
			return nil, fmt.Errorf("%w. baseline version or allow-dirty is required", cerr)
		}
		pending = migrations
		if e.baselineVer != "" {
			baseline := FilesLastIndex(migrations, func(f File) bool {
				return f.Version() == e.baselineVer
			})
			if baseline == -1 {
				return nil, fmt.Errorf("baseline version %q not found", e.baselineVer)
			}
			f := migrations[baseline]
			// Mark the revision in the database as baseline revision.
			if err := e.writeRevision(ctx, &Revision{Version: f.Version(), Description: f.Desc(), Type: RevisionTypeBaseline}); err != nil {
				return nil, err
			}
			pending = migrations[baseline+1:]
		}
	// Not the first time we execute and a custom starting point was provided.
	case e.fromVer != "":
		idx := FilesLastIndex(migrations, func(f File) bool {
			return f.Version() == e.fromVer
		})
		if idx == -1 {
			return nil, fmt.Errorf("starting point version %q not found in the migration directory", e.fromVer)
		}
		pending = migrations[idx:]
	default:
		var (
			last      = revs[len(revs)-1]
			partially = last.Applied != last.Total
			fn        = func(f File) bool { return f.Version() <= last.Version }
		)
		if partially {
			// If the last file is partially applied, we need to find the matching migration file in order to
			// continue execution at the correct statement.
			fn = func(f File) bool { return f.Version() == last.Version }
		}
		// Consider all migration files having a version < the latest revision version as pending. If the
		// last revision is partially applied, it is considered pending as well.
		idx := FilesLastIndex(migrations, fn)
		if idx == -1 {
			// If we cannot find the matching migration version for a partially applied migration,
			// error out since we cannot determine how to proceed from here.
			if partially {
				return nil, &MissingMigrationError{last.Version, last.Description}
			}
			// All migrations have a higher version than the latest revision. Take every migration file as pending.
			return migrations, nil
		}
		// If this file was not partially applied, take the next one.
		if last.Applied == last.Total {
			idx++
		}
		pending = migrations[idx:]
	}
	if len(pending) == 0 {
		return nil, ErrNoPendingFiles
	}
	return pending, nil
}

// Execute executes the given migration file on the database. If it sees a file, that has been partially applied, it
// will continue with the next statement in line.
func (e *Executor) Execute(ctx context.Context, m File) (err error) {
	hf, err := e.dir.Checksum()
	if err != nil {
		return fmt.Errorf("sql/migrate: execute: compute hash: %w", err)
	}
	hash, err := hf.SumByName(m.Name())
	if err != nil {
		return fmt.Errorf("sql/migrate: execute: scanning checksum from %q: %w", m.Name(), err)
	}
	stmts, err := m.Stmts()
	if err != nil {
		return fmt.Errorf("sql/migrate: execute: scanning statements from %q: %w", m.Name(), err)
	}
	// Create checksums for the statements.
	var (
		sums = make([]string, len(stmts))
		h    = sha256.New()
	)
	for i, stmt := range stmts {
		if _, err := h.Write([]byte(stmt)); err != nil {
			return err
		}
		sums[i] = base64.StdEncoding.EncodeToString(h.Sum(nil))
	}
	version := m.Version()
	// If there already is a revision with this version in the database,
	// and it is partially applied, continue where the last attempt was left off.
	r, err := e.rrw.ReadRevision(ctx, version)
	if err != nil && !errors.Is(err, ErrRevisionNotExist) {
		return fmt.Errorf("sql/migrate: execute: read revision: %w", err)
	}
	if errors.Is(err, ErrRevisionNotExist) {
		// Haven't seen this file before, create a new revision.
		r = &Revision{
			Version:     version,
			Description: m.Desc(),
			Type:        RevisionTypeExecute,
			Total:       len(stmts),
			Hash:        hash,
		}
	}
	// Save once to mark as started in the database.
	if err = e.writeRevision(ctx, r); err != nil {
		return err
	}
	// Make sure to store the Revision information.
	defer func(ctx context.Context, e *Executor, r *Revision) {
		if err2 := e.writeRevision(ctx, r); err2 != nil {
			err = wrap(err2, err)
		}
	}(ctx, e, r)
	if r.Applied > 0 {
		// If the file has been applied partially before, check if the
		// applied statements have not changed.
		for i := 0; i < r.Applied; i++ {
			if i > len(sums) || sums[i] != strings.TrimPrefix(r.PartialHashes[i], "h1:") {
				err = HistoryChangedError{m.Name(), i + 1}
				e.log.Log(LogError{Error: err})
				return err
			}
		}
	}
	e.log.Log(LogFile{r.Version, r.Description, r.Applied})
	for _, stmt := range stmts[r.Applied:] {
		e.log.Log(LogStmt{stmt})
		if _, err = e.drv.ExecContext(ctx, stmt); err != nil {
			e.log.Log(LogError{Error: err})
			r.setSQLErr(stmt, err)
			return fmt.Errorf("sql/migrate: execute: executing statement %q from version %q: %w", stmt, r.Version, err)
		}
		r.PartialHashes = append(r.PartialHashes, "h1:"+sums[r.Applied])
		r.Applied++
		if err = e.writeRevision(ctx, r); err != nil {
			return err
		}
	}
	r.done()
	return
}

func (e *Executor) writeRevision(ctx context.Context, r *Revision) error {
	r.ExecutedAt = time.Now()
	r.OperatorVersion = e.operator
	if err := e.rrw.WriteRevision(ctx, r); err != nil {
		return fmt.Errorf("sql/migrate: execute: write revision: %w", err)
	}
	return nil
}

// HistoryChangedError is returned if between two execution attempts already applied statements of a file have changed.
type HistoryChangedError struct {
	File string
	Stmt int
}

func (e HistoryChangedError) Error() string {
	return fmt.Sprintf("sql/migrate: execute: history changed: statement %d from file %q changed", e.Stmt, e.File)
}

// ExecuteN executes n pending migration files. If n<=0 all pending migration files are executed.
func (e *Executor) ExecuteN(ctx context.Context, n int) (err error) {
	pending, err := e.Pending(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		if n >= len(pending) {
			n = len(pending)
		}
		pending = pending[:n]
	}
	revs, err := e.rrw.ReadRevisions(ctx)
	if err != nil {
		return fmt.Errorf("sql/migrate: execute: read revisions: %w", err)
	}
	if err := LogIntro(e.log, revs, pending); err != nil {
		return err
	}
	for _, m := range pending {
		if err := e.Execute(ctx, m); err != nil {
			return err
		}
	}
	e.log.Log(LogDone{})
	return err
}

// Replay the migration directory and invoke the state to get back the inspection result.
func (e *Executor) Replay(ctx context.Context, r StateReader) (_ *schema.Realm, err error) {
	// Clean up after ourselves.
	restore, err := e.drv.(Snapshoter).Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("sql/migrate: taking database snapshot: %w", err)
	}
	defer func() {
		if err2 := restore(ctx); err2 != nil {
			err = wrap(err2, err)
		}
	}()
	// Replay the migration directory on the database.
	if err := e.ExecuteN(ctx, 0); err != nil && !errors.Is(err, ErrNoPendingFiles) {
		return nil, fmt.Errorf("sql/migrate: read migration directory state: %w", err)
	}
	return r.ReadState(ctx)
}

type (
	// Snapshoter wraps the Snapshot method.
	Snapshoter interface {
		// Snapshot takes a snapshot of the current database state and returns a function that can be called to restore
		// that state. Snapshot should return an error, if the current state can not be restored completely, e.g. if
		// there is a table already containing some rows.
		Snapshot(context.Context) (RestoreFunc, error)
	}

	// RestoreFunc is returned by the Snapshoter to explicitly restore the database state.
	RestoreFunc func(context.Context) error

	// TableIdent describes a table identifier returned by the revisions table.
	TableIdent struct {
		Name   string // name of the table.
		Schema string // optional schema.
	}

	// CleanChecker wraps the single CheckClean method.
	CleanChecker interface {
		// CheckClean checks if the connected realm or schema does not contain any resources besides the
		// revision history table. A NotCleanError is returned in case the connection is not-empty.
		CheckClean(context.Context, *TableIdent) error
	}

	// NotCleanError is returned when the connected dev-db is not in a clean state (aka it has schemas and tables).
	// This check is done to ensure no data is lost by overriding it when working on the dev-db.
	NotCleanError struct {
		Reason string // reason why the database is considered not clean
	}
)

func (e NotCleanError) Error() string {
	return "sql/migrate: connected database is not clean: " + e.Reason
}

// NopRevisionReadWriter is a RevisionReadWriter that does nothing.
// It is useful for one-time replay of the migration directory.
type NopRevisionReadWriter struct{}

// Ident implements RevisionsReadWriter.TableIdent.
func (NopRevisionReadWriter) Ident() *TableIdent {
	return nil
}

// ReadRevisions implements RevisionsReadWriter.ReadRevisions.
func (NopRevisionReadWriter) ReadRevisions(context.Context) ([]*Revision, error) {
	return nil, nil
}

// ReadRevision implements RevisionsReadWriter.ReadRevision.
func (NopRevisionReadWriter) ReadRevision(context.Context, string) (*Revision, error) {
	return nil, ErrRevisionNotExist
}

// WriteRevision implements RevisionsReadWriter.WriteRevision.
func (NopRevisionReadWriter) WriteRevision(context.Context, *Revision) error {
	return nil
}

// DeleteRevision implements RevisionsReadWriter.DeleteRevision.
func (NopRevisionReadWriter) DeleteRevision(context.Context, string) error {
	return nil
}

var _ RevisionReadWriter = (*NopRevisionReadWriter)(nil)

// done computes and sets the ExecutionTime.
func (r *Revision) done() {
	r.ExecutionTime = time.Now().Sub(r.ExecutedAt)
}

func (r *Revision) setSQLErr(stmt string, err error) {
	r.done()
	r.Error = fmt.Sprintf("Statement:\n%s\n\nError:\n%s", stmt, err)
}

type (
	// A Logger logs migration execution.
	Logger interface {
		Log(LogEntry)
	}

	// LogEntry marks several types of logs to be passed to a Logger.
	LogEntry interface {
		logEntry()
	}

	// LogExecution is sent once when execution of multiple migration files has been started.
	// It holds the filenames of the pending migration files.
	LogExecution struct {
		// From what version.
		From string
		// To what version.
		To string
		// Migration Files to be executed.
		Files []string
	}

	// LogFile is sent if a new migration file is executed.
	LogFile struct {
		// Version executed.
		Version string
		// Desc of migration executed.
		Desc string
		// Skip holds the number of stmts of this file that will be skipped.
		// This happens, if a migration file was only applied partially and will now continue to be applied.
		Skip int
	}

	// LogStmt is sent if a new SQL statement is executed.
	LogStmt struct {
		SQL string
	}

	// LogDone is sent if the execution is done.
	LogDone struct{}

	// LogError is sent if there is an error while execution.
	LogError struct {
		Error error
	}

	// NopLogger is a Logger that does nothing.
	// It is useful for one-time replay of the migration directory.
	NopLogger struct{}
)

func (LogExecution) logEntry() {}
func (LogFile) logEntry()      {}
func (LogStmt) logEntry()      {}
func (LogDone) logEntry()      {}
func (LogError) logEntry()     {}

// Log implements the Logger interface.
func (NopLogger) Log(LogEntry) {}

// LogIntro gathers some meta information from the migration files and stored revisions to
// log some general information prior to actual execution.
func LogIntro(l Logger, revs []*Revision, files []File) error {
	names := make([]string, len(files))
	for i := range files {
		names[i] = files[i].Name()
	}
	last := files[len(files)-1]
	e := LogExecution{To: last.Version(), Files: names}
	if len(revs) > 0 {
		e.From = revs[len(revs)-1].Version
	}
	l.Log(e)
	return nil
}

func wrap(err1, err2 error) error {
	if err2 != nil {
		return fmt.Errorf("sql/migrate: %w: %v", err2, err1)
	}
	return err1
}
