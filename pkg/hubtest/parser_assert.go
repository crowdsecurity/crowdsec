package hubtest

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/expr-lang/expr"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/maptools"

	"github.com/crowdsecurity/crowdsec/pkg/dumps"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

type AssertFail struct {
	File       string
	Line       int
	Expression string
	Debug      map[string]string
}

type ParserAssert struct {
	File              string
	AutoGenAssert     bool
	AutoGenAssertData string
	NbAssert          int
	Fails             []AssertFail
	Success           bool
	TestData          *dumps.ParserResults
}

func NewParserAssert(file string) *ParserAssert {
	ParserAssert := &ParserAssert{
		File:          file,
		NbAssert:      0,
		Success:       false,
		Fails:         make([]AssertFail, 0),
		AutoGenAssert: false,
		TestData:      &dumps.ParserResults{},
	}

	return ParserAssert
}

func (p *ParserAssert) AutoGenFromFile(filename string) (string, error) {
	err := p.LoadTest(filename)
	if err != nil {
		return "", err
	}

	ret := p.AutoGenParserAssert()

	return ret, nil
}

func (p *ParserAssert) LoadTest(filename string) error {
	parserDump, err := dumps.LoadParserDump(filename)
	if err != nil {
		return fmt.Errorf("loading parser dump file: %+v", err)
	}

	p.TestData = parserDump

	return nil
}

func (p *ParserAssert) AssertFile(testFile string) error {
	file, err := os.Open(p.File)
	if err != nil {
		return errors.New("failed to open")
	}

	if err := p.LoadTest(testFile); err != nil {
		return fmt.Errorf("unable to load parser dump file '%s': %w", testFile, err)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	nbLine := 0

	for scanner.Scan() {
		nbLine++

		if scanner.Text() == "" {
			continue
		}

		ok, err := p.Run(scanner.Text())
		if err != nil {
			return fmt.Errorf("unable to run assert '%s': %+v", scanner.Text(), err)
		}

		p.NbAssert++

		if !ok {
			log.Debugf("%s is FALSE", scanner.Text())
			failedAssert := &AssertFail{
				File:       p.File,
				Line:       nbLine,
				Expression: scanner.Text(),
				Debug:      make(map[string]string),
			}

			match := variableRE.FindStringSubmatch(scanner.Text())

			var variable string

			if len(match) == 0 {
				log.Infof("Couldn't get variable of line '%s'", scanner.Text())
				variable = scanner.Text()
			} else {
				variable = match[1]
			}

			result, err := p.EvalExpression(variable)
			if err != nil {
				log.Errorf("unable to evaluate variable '%s': %s", variable, err)
				continue
			}

			failedAssert.Debug[variable] = result
			p.Fails = append(p.Fails, *failedAssert)

			continue
		}
		// fmt.Printf(" %s '%s'\n", emoji.GreenSquare, scanner.Text())
	}

	file.Close()

	if p.NbAssert == 0 {
		assertData, err := p.AutoGenFromFile(testFile)
		if err != nil {
			return fmt.Errorf("couldn't generate assertion: %w", err)
		}

		p.AutoGenAssertData = assertData
		p.AutoGenAssert = true
	}

	if len(p.Fails) == 0 {
		p.Success = true
	}

	return nil
}

func (p *ParserAssert) RunExpression(expression string) (interface{}, error) {
	// debug doesn't make much sense with the ability to evaluate "on the fly"
	// var debugFilter *exprhelpers.ExprDebugger
	var output interface{}

	env := map[string]interface{}{"results": *p.TestData}

	runtimeFilter, err := expr.Compile(expression, exprhelpers.GetExprOptions(env)...)
	if err != nil {
		log.Errorf("failed to compile '%s' : %s", expression, err)
		return output, err
	}

	// dump opcode in trace level
	log.Tracef("%s", runtimeFilter.Disassemble())

	output, err = expr.Run(runtimeFilter, env)
	if err != nil {
		log.Warningf("running : %s", expression)
		log.Warningf("runtime error : %s", err)

		return output, fmt.Errorf("while running expression %s: %w", expression, err)
	}

	return output, nil
}

func (p *ParserAssert) EvalExpression(expression string) (string, error) {
	output, err := p.RunExpression(expression)
	if err != nil {
		return "", err
	}

	ret, err := yaml.Marshal(output)
	if err != nil {
		return "", err
	}

	return string(ret), nil
}

func (p *ParserAssert) Run(assert string) (bool, error) {
	output, err := p.RunExpression(assert)
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

func Escape(val string) string {
	val = strings.ReplaceAll(val, `\`, `\\`)
	val = strings.ReplaceAll(val, `"`, `\"`)

	return val
}

func (p *ParserAssert) AutoGenParserAssert() string {
	// attempt to autogen parser asserts
	ret := fmt.Sprintf("len(results) == %d\n", len(*p.TestData))

	// sort map keys for consistent order
	stages := maptools.SortedKeys(*p.TestData)

	for _, stage := range stages {
		parsers := (*p.TestData)[stage]

		// sort map keys for consistent order
		pnames := maptools.SortedKeys(parsers)

		for _, parser := range pnames {
			presults := parsers[parser]
			ret += fmt.Sprintf(`len(results["%s"]["%s"]) == %d`+"\n", stage, parser, len(presults))

			for pidx, result := range presults {
				ret += fmt.Sprintf(`results["%s"]["%s"][%d].Success == %t`+"\n", stage, parser, pidx, result.Success)

				if !result.Success {
					continue
				}

				for _, pkey := range maptools.SortedKeys(result.Evt.Parsed) {
					pval := result.Evt.Parsed[pkey]
					if pval == "" {
						continue
					}

					ret += fmt.Sprintf(`results["%s"]["%s"][%d].Evt.Parsed["%s"] == "%s"`+"\n", stage, parser, pidx, pkey, Escape(pval))
				}

				for _, mkey := range maptools.SortedKeys(result.Evt.Meta) {
					mval := result.Evt.Meta[mkey]
					if mval == "" {
						continue
					}

					ret += fmt.Sprintf(`results["%s"]["%s"][%d].Evt.Meta["%s"] == "%s"`+"\n", stage, parser, pidx, mkey, Escape(mval))
				}

				for _, ekey := range maptools.SortedKeys(result.Evt.Enriched) {
					eval := result.Evt.Enriched[ekey]
					if eval == "" {
						continue
					}

					ret += fmt.Sprintf(`results["%s"]["%s"][%d].Evt.Enriched["%s"] == "%s"`+"\n", stage, parser, pidx, ekey, Escape(eval))
				}

				for _, ukey := range maptools.SortedKeys(result.Evt.Unmarshaled) {
					uval := result.Evt.Unmarshaled[ukey]
					if uval == "" {
						continue
					}

					base := fmt.Sprintf("results[%q][%q][%d].Evt.Unmarshaled[%q]", stage, parser, pidx, ukey)

					for _, line := range p.buildUnmarshaledAssert(base, uval) {
						ret += line
					}
				}

				ret += fmt.Sprintf(`results["%s"]["%s"][%d].Evt.Whitelisted == %t`+"\n", stage, parser, pidx, result.Evt.Whitelisted)

				if result.Evt.WhitelistReason != "" {
					ret += fmt.Sprintf(`results["%s"]["%s"][%d].Evt.WhitelistReason == "%s"`+"\n", stage, parser, pidx, Escape(result.Evt.WhitelistReason))
				}
			}
		}
	}

	return ret
}

func (p *ParserAssert) buildUnmarshaledAssert(ekey string, eval interface{}) []string {
	ret := make([]string, 0)

	switch val := eval.(type) {
	case map[string]interface{}:
		for k, v := range val {
			ret = append(ret, p.buildUnmarshaledAssert(fmt.Sprintf("%s[%q]", ekey, k), v)...)
		}
	case map[interface{}]interface{}:
		for k, v := range val {
			ret = append(ret, p.buildUnmarshaledAssert(fmt.Sprintf("%s[%q]", ekey, k), v)...)
		}
	case []interface{}:
	case string:
		ret = append(ret, fmt.Sprintf(`%s == "%s"`+"\n", ekey, Escape(val)))
	case bool:
		ret = append(ret, fmt.Sprintf(`%s == %t`+"\n", ekey, val))
	case int:
		ret = append(ret, fmt.Sprintf(`%s == %d`+"\n", ekey, val))
	case float64:
		ret = append(ret, fmt.Sprintf(`FloatApproxEqual(%s, %f)`+"\n",
			ekey, val))
	default:
		log.Warningf("unknown type '%T' for key '%s'", val, ekey)
	}

	return ret
}
