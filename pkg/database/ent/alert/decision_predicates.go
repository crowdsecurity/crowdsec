package alert

import (
	"entgo.io/ent/dialect/sql"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
)

// HasDecisionsMatching keeps independent decision filters as independent subqueries,
// but avoids correlated EXISTS plans that are expensive for SQLite on large decision sets.
func HasDecisionsMatching(preds ...predicate.Decision) predicate.Alert {
	return predicate.Alert(func(selector *sql.Selector) {
		decisions := sql.Select(DecisionsColumn).From(sql.Table(DecisionsTable))
		for _, pred := range preds {
			pred(decisions)
		}
		selector.Where(sql.In(selector.C(FieldID), decisions))
	})
}
