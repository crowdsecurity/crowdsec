package parser

import (
	"errors"
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/crowdsecurity/grokky"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type GrokPattern struct {
	TargetField string `yaml:"apply_on,omitempty"`   // the field to which regexp is going to apply
	RegexpName string  `yaml:"name,omitempty"`       // the grok/regexp by name (loaded from patterns/*)
	RegexpValue string `yaml:"pattern,omitempty"`    // a proper grok pattern
	ExpValue string    `yaml:"expression,omitempty"` // the output of the expression is going to be the source for regexp
	Statics []Static   `yaml:"statics,omitempty"`    // a grok can contain statics that apply if pattern is successful
}

type RuntimeGrokPattern struct {
	Config *GrokPattern

	RunTimeRegexp  grokky.Pattern // the actual regexp
	RunTimeValue   *vm.Program    // the actual compiled filter
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

		logger.Tracef("%s regexp: %s", g.RegexpValue, rg.RunTimeRegexp.String())
	}

	// if grok source is an expression
	if g.ExpValue != "" {
		rg.RunTimeValue, err = expr.Compile(g.ExpValue,
			exprhelpers.GetExprOptions(map[string]any{"evt": &pipeline.Event{}})...)
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

func (g *GrokPattern) Validate() error {
	if g.TargetField == "" && g.ExpValue == "" {
		return errors.New("grok requires 'expression' or 'apply_on'")
	}

	if g.RegexpName == "" && g.RegexpValue == "" {
		return errors.New("grok needs 'pattern' or 'name'")
	}

	return nil
}
