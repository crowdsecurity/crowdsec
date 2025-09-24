package parser

import (
	"errors"
	"fmt"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/crowdsecurity/grokky"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type Static struct {
	// if the target is indicated by name Struct.Field etc,
	TargetByName string `yaml:"target,omitempty"`
	// if the target field is in Event map
	Parsed string `yaml:"parsed,omitempty"`
	// if the target field is in Meta map
	Meta string `yaml:"meta,omitempty"`
	// if the target field is in Enriched map
	Enriched string `yaml:"enriched,omitempty"`
	// the source is a static value
	Value string `yaml:"value,omitempty"`
	// or the result of an Expression
	ExpValue     string      `yaml:"expression,omitempty"`
	// or an enrichment method
	Method string `yaml:"method,omitempty"`
}

type RuntimeStatic struct {
	Config *Static
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
			exprhelpers.GetExprOptions(map[string]any{"evt": &types.Event{}})...)
		if err != nil {
			return nil, fmt.Errorf("compiling static expression %q: %w", s.ExpValue, err)
		}

		cs.RunTimeValue = prog
	}

	return cs, nil
}

type GrokPattern struct {
	// the field to which regexp is going to apply
	TargetField string `yaml:"apply_on,omitempty"`
	// the grok/regexp by name (loaded from patterns/*)
	RegexpName string `yaml:"name,omitempty"`
	// a proper grok pattern
	RegexpValue string `yaml:"pattern,omitempty"`
	// the runtime form of regexpname / regexpvalue
	RunTimeRegexp grokky.Pattern `yaml:"-"` // the actual regexp
	// the output of the expression is going to be the source for regexp
	ExpValue     string      `yaml:"expression,omitempty"`
	RunTimeValue *vm.Program `yaml:"-"` // the actual compiled filter
	// a grok can contain statics that apply if pattern is successful
	Statics []Static `yaml:"statics,omitempty"`
	RuntimeStatics []RuntimeStatic `yaml:"-"`
}

type DataCapture struct {
	Name            string        `yaml:"name,omitempty"`
	Key             string        `yaml:"key,omitempty"`
	KeyExpression   *vm.Program   `yaml:"-"`
	Value           string        `yaml:"value,omitempty"`
	ValueExpression *vm.Program   `yaml:"-"`
	TTL             string        `yaml:"ttl,omitempty"`
	TTLVal          time.Duration `yaml:"-"`
	MaxMapSize      int           `yaml:"size,omitempty"`
	Strategy        string        `yaml:"strategy,omitempty"`
}
