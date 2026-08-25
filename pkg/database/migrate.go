package database

import (
	atlas "ariga.io/atlas/sql/schema"
	entschema "entgo.io/ent/dialect/sql/schema"
)

// dropLegacyIndex drops an index that is no longer part of the ent schema.
//
// Schema.Create() never emits DropIndex on its own, and the WithDropIndex option
// that would enable it is too broad: it removes every index missing from the ent
// schema, including ones an operator added by hand. Diff hooks wrap the default
// filter, so the change can be put back for one named index only.
func dropLegacyIndex(table, index string) entschema.MigrateOption {
	return entschema.WithDiffHook(func(next entschema.Differ) entschema.Differ {
		return entschema.DiffFunc(func(current, desired *atlas.Schema) ([]atlas.Change, error) {
			changes, err := next.Diff(current, desired)
			if err != nil {
				return nil, err
			}

			t, ok := current.Table(table)
			if !ok {
				return changes, nil
			}

			idx, ok := t.Index(index)
			if !ok {
				return changes, nil
			}

			drop := &atlas.DropIndex{I: idx}

			// Fold into the table's pending changes when there are some, so the
			// drop and the replacement index are planned together.
			for _, c := range changes {
				if m, ok := c.(*atlas.ModifyTable); ok && m.T.Name == table {
					m.Changes = append(m.Changes, drop)
					return changes, nil
				}
			}

			return append(changes, &atlas.ModifyTable{T: t, Changes: []atlas.Change{drop}}), nil
		})
	})
}
