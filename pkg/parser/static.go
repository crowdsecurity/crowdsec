package parser

import (
	"errors"
	"fmt"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Static struct {
	TargetByName string `yaml:"target,omitempty"`     // if the target is indicated by name Struct.Field etc,
	Parsed string       `yaml:"parsed,omitempty"`     // if the target field is in Event map
	Meta string         `yaml:"meta,omitempty"`       // if the target field is in Meta map
	Enriched string     `yaml:"enriched,omitempty"`   // if the target field is in Enriched map
	Value string        `yaml:"value,omitempty"`      // the source is a static value
	ExpValue string     `yaml:"expression,omitempty"` // or the result of an Expression
	Method string       `yaml:"method,omitempty"`     // or an enrichment method
}

type RuntimeStatic struct {
	Config       *Static
	RunTimeValue *vm.Program
}

func (s *Static) Validate(ectx EnricherCtx) error {
	if s.Method != "" {
		if s.Value == "" && s.ExpValue == "" {
			return errors.New("when method is set, expression must be present")
		}

		if _, ok := ectx.Registered[s.Method]; !ok {
			log.Warningf("the method %q doesn't exist or the plugin has not been initialized", s.Method)
		}

		return nil
	}

	if s.Meta == "" && s.Parsed == "" && s.TargetByName == "" {
		return errors.New("at least one of meta/event/target must be set")
	}

	if s.Value == "" && s.ExpValue == "" {
		return errors.New("value or expression must be set")
	}

	return nil
}

func (s *Static) Compile() (*RuntimeStatic, error) {
	cs := &RuntimeStatic{Config: s}

	if s.ExpValue != "" {
		prog, err := expr.Compile(s.ExpValue,
			exprhelpers.GetExprOptions(map[string]any{"evt": &pipeline.Event{}})...)
		if err != nil {
			return nil, fmt.Errorf("compiling static expression %q: %w", s.ExpValue, err)
		}

		cs.RunTimeValue = prog
	}

	return cs, nil
}
