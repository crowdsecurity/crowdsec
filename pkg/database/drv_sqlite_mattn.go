//go:build !db_no_sqlite && !sqlite_modernc

package database

import (
	"errors"

	"github.com/mattn/go-sqlite3"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion/component"
)

//nolint:gochecknoinits
func init() {
	component.Register("db_sqlite")
}

func IsSqliteBusyError(err error) bool {
	var sqliteErr sqlite3.Error
	return errors.As(err, &sqliteErr) && sqliteErr.Code == sqlite3.ErrBusy
}
