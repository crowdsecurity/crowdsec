//go:build !no_db_postgres

package database

import (
	// register database driver as side effect
	_ "github.com/jackc/pgx/v4/stdlib"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion/component"
)

//nolint:gochecknoinits
func init() {
	component.Register("db_postgres")
}
