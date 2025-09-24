package parser

import (
	"errors"
	"fmt"
	"strings"
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
	// the output of the expression is going to be the source for regexp
	ExpValue     string      `yaml:"expression,omitempty"`
	// a grok can contain statics that apply if pattern is successful
	Statics []Static `yaml:"statics,omitempty"`
}

type RuntimeGrokPattern struct {
	Config *GrokPattern

	RunTimeRegexp  grokky.Pattern  // the actual regexp
	RunTimeValue   *vm.Program     // the actual compiled filter
	RuntimeStatics []RuntimeStatic
}

func (g *GrokPattern) Compile(pctx *UnixParserCtx, logger *log.Entry) (*RuntimeGrokPattern, error) {
	var err error

	rg := &RuntimeGrokPattern{}
	/* load grok by name or compile in-place */
	if g.RegexpName != "" {
		logger.Tracef("+ Regexp Compilation %q", g.RegexpName)

		rg.RunTimeRegexp, err = pctx.Grok.Get(g.RegexpName)
		if err != nil {
			return nil, fmt.Errorf("unable to find grok %q: %v", g.RegexpName, err)
		}

		if rg.RunTimeRegexp == nil {
			return nil, fmt.Errorf("empty grok %q", g.RegexpName)
		}

		logger.Tracef("%s regexp: %s", g.RegexpName, rg.RunTimeRegexp.String())
	} else if g.RegexpValue != "" {
		if strings.HasSuffix(g.RegexpValue, "\n") {
			logger.Debugf("Beware, pattern ends with \\n: %q", g.RegexpValue)
		}

		rg.RunTimeRegexp, err = pctx.Grok.Compile(g.RegexpValue)
		if err != nil {
			return nil, fmt.Errorf("failed to compile grok %q: %v", g.RegexpValue, err)
		}

		if rg.RunTimeRegexp == nil {
			// We shouldn't be here because compilation succeeded, so regexp shouldn't be nil
			return nil, fmt.Errorf("grok compilation failure: %s", g.RegexpValue)
		}

		logger.Tracef("%s regexp: %s", g.RegexpValue, rg.RunTimeRegexp.String())
	}

	// if grok source is an expression
	if g.ExpValue != "" {
		rg.RunTimeValue, err = expr.Compile(g.ExpValue,
			exprhelpers.GetExprOptions(map[string]any{"evt": &types.Event{}})...)
		if err != nil {
			return nil, fmt.Errorf("while compiling grok's expression: %w", err)
		}
	}

	/* load grok statics */
	// compile expr statics if present
	for _, static := range g.Statics {
		compiled, err := static.Compile()
		if err != nil {
			return nil, err
		}

		rg.RuntimeStatics = append(rg.RuntimeStatics, *compiled)
	}

	return rg, nil
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
