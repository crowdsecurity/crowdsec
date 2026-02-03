package leakybucket

import (
	"errors"
	"fmt"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type ScopeType struct {
	Scope         string `yaml:"type"`
	Filter        string `yaml:"expression"`
	RunTimeFilter *vm.Program
}

func (s *ScopeType) CompileFilter() error {
	if s.Scope == types.Undefined {
		s.Scope = types.Ip
	}

	if s.Scope == types.Ip {
		if s.Filter != "" {
			return errors.New("filter is not allowed for IP scope")
		}

		return nil
	}

	if s.Scope == types.Range && s.Filter == "" {
		return nil
	}

	if s.Filter == "" {
		return errors.New("filter is mandatory for non-IP, non-Range scope")
	}

	runTimeFilter, err := expr.Compile(s.Filter, exprhelpers.GetExprOptions(map[string]any{"evt": &pipeline.Event{}})...)
	if err != nil {
		return fmt.Errorf("error compiling the scope filter: %w", err)
	}

	s.RunTimeFilter = runTimeFilter

	return nil
}
