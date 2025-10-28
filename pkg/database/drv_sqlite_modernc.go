//go:build !db_no_sqlite && sqlite_modernc

package database

import (
	"database/sql"
	"errors"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion/component"
)

//nolint:gochecknoinits
func init() {
	sql.Register("sqlite3", &sqlite.Driver{})
	component.Register("db_sqlite")
}

func IsSqliteBusyError(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code() == sqlite3.SQLITE_BUSY
}
