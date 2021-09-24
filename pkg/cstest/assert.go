package cstest

import (
	"fmt"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

func autogenParserAssertsFromFile(filename string) (string, error) {
	pdump, err := LoadParserDump(filename)
	if err != nil {
		return "", err
	}
	ret := autogenParserAsserts(pdump)
	return ret, nil
}

func RunExpression(expression string, results ParserResults) (interface{}, error) {
	var err error
	//debug doesn't make much sense with the ability to evaluate "on the fly"
	//var debugFilter *exprhelpers.ExprDebugger
	var runtimeFilter *vm.Program
	var output interface{}

	env := map[string]interface{}{"results": results}

	if runtimeFilter, err = expr.Compile(expression, expr.Env(exprhelpers.GetExprEnv(env))); err != nil {
		return output, err
	}
	// if debugFilter, err = exprhelpers.NewDebugger(assert, expr.Env(exprhelpers.GetExprEnv(env))); err != nil {
	// 	log.Warningf("Failed building debugher for %s : %s", assert, err)
	// }

	//dump opcode in trace level
	log.Tracef("%s", runtimeFilter.Disassemble())

	output, err = expr.Run(runtimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"results": results}))
	if err != nil {
		log.Warningf("running : %s", expression)
		log.Warningf("runtime error : %s", err)
		return output, errors.Wrapf(err, "while running expression %s", expression)
	}
	return output, nil
}

func EvalExpression(expression string, results ParserResults) (string, error) {
	output, err := RunExpression(expression, results)
	if err != nil {
		return "", err
	}
	ret, err := yaml.Marshal(output)
	if err != nil {
		return "", err
	}
	return string(ret), nil
}

func runOneParserAssert(assert string, results ParserResults) (bool, error) {
	output, err := RunExpression(assert, results)
	if err != nil {
		return false, err
	}
	switch out := output.(type) {
	case bool:
		return out, nil
	default:
		return false, fmt.Errorf("assertion '%s' is not a condition", assert)
	}
}

func autogenParserAsserts(parserResults ParserResults) string {
	//attempt to autogen parser asserts
	var ret string
	for stage, parsers := range parserResults {
		for parser, presults := range parsers {
			for pidx, result := range presults {
				ret += fmt.Sprintf(`results["%s"]["%s"][%d].Success == %t`+"\n", stage, parser, pidx, result.Success)

				for pkey, pval := range result.Evt.Parsed {
					if pval == "" {
						continue
					}
					ret += fmt.Sprintf(`results["%s"]["%s"][%d].Evt.Parsed["%s"] == "%s"`+"\n", stage, parser, pidx, pkey, pval)
				}
				for mkey, mval := range result.Evt.Meta {
					if mval == "" {
						continue
					}
					ret += fmt.Sprintf(`results["%s"]["%s"][%d].Evt.Meta["%s"] == "%s"`+"\n", stage, parser, pidx, mkey, mval)
				}
			}
		}
	}
	return ret
}
