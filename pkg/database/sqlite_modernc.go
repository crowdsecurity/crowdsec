//go:build sqlite_modernc

package database

import (
	"errors"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func IsSqliteBusyError(err error) bool {
	var se *sqlite.Error

	if errors.As(err, &se) {
		return se.Code() == sqlite3.SQLITE_BUSY
	}

	return false
}
