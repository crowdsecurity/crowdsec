//go:build !no_db_mysql

package database

import (
	// register database driver as side effect
	_ "github.com/go-sql-driver/mysql"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion/component"
)

//nolint:gochecknoinits
func init() {
	component.Register("db_mysql")
}
