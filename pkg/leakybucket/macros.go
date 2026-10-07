package leakybucket

import (
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

// expressions returns every expression of the scenario.
// TestBucketSpecExpressions fails if a string field is added without being classified.
func (s *BucketSpec) expressions() []string {
	all := []string{s.Filter, s.GroupBy, s.Distinct, s.CancelOnFilter, s.ConditionalOverflow, s.OverflowFilter, s.ScopeType.Filter}
	for _, c := range s.BayesianConditions {
		all = append(all, c.ConditionalFilterName)
	}

	ret := make([]string, 0, len(all))

	for _, e := range all {
		if e != "" {
			ret = append(ret, e)
		}
	}

	return ret
}

// untrustedMacroItem returns the first macro item used by the scenario that was
// modified or isn't from the hub: the scenario's behavior no longer matches its hash.
func untrustedMacroItem(hub *cwhub.Hub, spec *BucketSpec) (string, error) {
	for _, e := range spec.expressions() {
		items, err := exprhelpers.MacroItems(e)
		if err != nil {
			return "", err
		}

		for _, name := range items {
			item := hub.GetItem(cwhub.MACROS, name)
			if item == nil || item.State.IsLocal() || item.State.Tainted {
				return name, nil
			}
		}
	}

	return "", nil
}
