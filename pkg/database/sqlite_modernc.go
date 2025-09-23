//go:build sqlite_modernc

package database

import (
	"errors"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func IsSqliteBusyError(err error) bool {
	var sqliteErr sqlite.Error
	return errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_BUSY
}
