//go:build !sqlite_modernc

package database

import (
	"errors"

	"github.com/mattn/go-sqlite3"
)

func IsSqliteBusyError(err error) bool {
	var sqliteErr sqlite3.Error
	// sqlite3.Error{
	//   Code:         5,
	//   ExtendedCode: 5,
	//   SystemErrno:  0,
	//   err:          "database is locked",
	// }
	return errors.As(err, &sqliteErr) && sqliteErr.Code == sqlite3.ErrBusy
}
