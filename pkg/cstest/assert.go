package cstest

import (
	"fmt"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func autogenParserAssertsFromFile(filename string) (string, error) {
	pdump, err := loadParserDump(filename)
	if err != nil {
		return "", err
	}
	ret := autogenParserAsserts(pdump)
	return ret, nil
}

func runOneParserAssert(assert string, results ParserResults) (bool, error, bool) {
	var err error
	//debug doesn't make much sense with the ability to evaluate "on the fly"
	//var debugFilter *exprhelpers.ExprDebugger
	var runtimeFilter *vm.Program
	var output interface{}

	env := map[string]interface{}{"results": results}

	if runtimeFilter, err = expr.Compile(assert, expr.Env(exprhelpers.GetExprEnv(env))); err != nil {
		log.Fatalf(err.Error())
	}
	// if debugFilter, err = exprhelpers.NewDebugger(assert, expr.Env(exprhelpers.GetExprEnv(env))); err != nil {
	// 	log.Warningf("Failed building debugher for %s : %s", assert, err)
	// }

	//dump opcode in trace level
	log.Tracef("%s", runtimeFilter.Disassemble())

	output, err = expr.Run(runtimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"results": results}))
	if err != nil {
		log.Warningf("running : %s", assert)
		log.Warningf("runtime error : %s", err)
		return false, errors.Wrapf(err, "while running expression %s", assert), false
	}
	switch out := output.(type) {
	case bool:
		// if out == false || logger.Level >= log.DebugLevel {
		// 	log.Printf("call debug thinggy")
		// 	debugFilter.Run(logger, true, exprhelpers.GetExprEnv(map[string]interface{}{"results": results}))
		// }
		if output == true {
			return true, nil, false
		} else {
			return false, nil, false
		}
	default:
		log.Printf("%s -> %s", assert, spew.Sdump(out))
		return true, nil, true
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
