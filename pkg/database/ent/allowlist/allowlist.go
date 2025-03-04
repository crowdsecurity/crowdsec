// Code generated by ent, DO NOT EDIT.

package allowlist

import (
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

const (
	// Label holds the string label denoting the allowlist type in the database.
	Label = "allow_list"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldCreatedAt holds the string denoting the created_at field in the database.
	FieldCreatedAt = "created_at"
	// FieldUpdatedAt holds the string denoting the updated_at field in the database.
	FieldUpdatedAt = "updated_at"
	// FieldName holds the string denoting the name field in the database.
	FieldName = "name"
	// FieldFromConsole holds the string denoting the from_console field in the database.
	FieldFromConsole = "from_console"
	// FieldDescription holds the string denoting the description field in the database.
	FieldDescription = "description"
	// FieldAllowlistID holds the string denoting the allowlist_id field in the database.
	FieldAllowlistID = "allowlist_id"
	// EdgeAllowlistItems holds the string denoting the allowlist_items edge name in mutations.
	EdgeAllowlistItems = "allowlist_items"
	// Table holds the table name of the allowlist in the database.
	Table = "allow_lists"
	// AllowlistItemsTable is the table that holds the allowlist_items relation/edge. The primary key declared below.
	AllowlistItemsTable = "allow_list_allowlist_items"
	// AllowlistItemsInverseTable is the table name for the AllowListItem entity.
	// It exists in this package in order to avoid circular dependency with the "allowlistitem" package.
	AllowlistItemsInverseTable = "allow_list_items"
)

// Columns holds all SQL columns for allowlist fields.
var Columns = []string{
	FieldID,
	FieldCreatedAt,
	FieldUpdatedAt,
	FieldName,
	FieldFromConsole,
	FieldDescription,
	FieldAllowlistID,
}

var (
	// AllowlistItemsPrimaryKey and AllowlistItemsColumn2 are the table columns denoting the
	// primary key for the allowlist_items relation (M2M).
	AllowlistItemsPrimaryKey = []string{"allow_list_id", "allow_list_item_id"}
)

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultCreatedAt holds the default value on creation for the "created_at" field.
	DefaultCreatedAt func() time.Time
	// DefaultUpdatedAt holds the default value on creation for the "updated_at" field.
	DefaultUpdatedAt func() time.Time
	// UpdateDefaultUpdatedAt holds the default value on update for the "updated_at" field.
	UpdateDefaultUpdatedAt func() time.Time
)

// OrderOption defines the ordering options for the AllowList queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByCreatedAt orders the results by the created_at field.
func ByCreatedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCreatedAt, opts...).ToFunc()
}

// ByUpdatedAt orders the results by the updated_at field.
func ByUpdatedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldUpdatedAt, opts...).ToFunc()
}

// ByName orders the results by the name field.
func ByName(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldName, opts...).ToFunc()
}

// ByFromConsole orders the results by the from_console field.
func ByFromConsole(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldFromConsole, opts...).ToFunc()
}

// ByDescription orders the results by the description field.
func ByDescription(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldDescription, opts...).ToFunc()
}

// ByAllowlistID orders the results by the allowlist_id field.
func ByAllowlistID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldAllowlistID, opts...).ToFunc()
}

// ByAllowlistItemsCount orders the results by allowlist_items count.
func ByAllowlistItemsCount(opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborsCount(s, newAllowlistItemsStep(), opts...)
	}
}

// ByAllowlistItems orders the results by allowlist_items terms.
func ByAllowlistItems(term sql.OrderTerm, terms ...sql.OrderTerm) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newAllowlistItemsStep(), append([]sql.OrderTerm{term}, terms...)...)
	}
}
func newAllowlistItemsStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(AllowlistItemsInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2M, false, AllowlistItemsTable, AllowlistItemsPrimaryKey...),
	)
}
