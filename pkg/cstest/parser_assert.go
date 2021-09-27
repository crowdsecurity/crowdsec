package cstest

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/enescakir/emoji"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type ParserAssert struct {
	File              string
	AutoGenAssert     bool
	AutoGenAssertData string
	NbAssert          int
	Fails             []string
	Success           bool
	TestData          *ParserResults
}

type parserResult struct {
	Evt     types.Event
	Success bool
}
type ParserResults map[string]map[string][]parserResult

func NewParserAssert(file string) (*ParserAssert, error) {
	ParserAssert := &ParserAssert{
		File:          file,
		NbAssert:      0,
		Success:       false,
		Fails:         make([]string, 0),
		AutoGenAssert: false,
		TestData:      &ParserResults{},
	}
	return ParserAssert, nil
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
	var err error
	parserDump, err := LoadParserDump(filename)
	if err != nil {
		return fmt.Errorf("loading parser dump file: %+v", err)
	}
	p.TestData = parserDump
	return nil
}

func (p *ParserAssert) AssertFile(testFile string) error {
	file, err := os.Open(p.File)

	if err != nil {
		return fmt.Errorf("failed to open")
	}

	if err := p.LoadTest(testFile); err != nil {
		return fmt.Errorf("unable to load parser dump file '%s': %s", testFile, err)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		ok, err := p.Run(scanner.Text())
		if err != nil {
			return fmt.Errorf("unable to run assert '%s': %+v", scanner.Text(), err)
		}
		p.NbAssert += 1
		if !ok {
			log.Debugf("%s is FALSE", scanner.Text())
			//fmt.SPrintf(" %s '%s'\n", emoji.RedSquare, scanner.Text())
			p.Fails = append(p.Fails, scanner.Text())
			continue
		}
		//fmt.Printf(" %s '%s'\n", emoji.GreenSquare, scanner.Text())

	}
	file.Close()
	if p.NbAssert == 0 {
		assertData, err := p.AutoGenFromFile(testFile)
		if err != nil {
			return fmt.Errorf("couldn't generate assertion: %s", err.Error())
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
	var err error
	//debug doesn't make much sense with the ability to evaluate "on the fly"
	//var debugFilter *exprhelpers.ExprDebugger
	var runtimeFilter *vm.Program
	var output interface{}

	env := map[string]interface{}{"results": p.TestData}

	if runtimeFilter, err = expr.Compile(expression, expr.Env(exprhelpers.GetExprEnv(env))); err != nil {
		return output, err
	}
	// if debugFilter, err = exprhelpers.NewDebugger(assert, expr.Env(exprhelpers.GetExprEnv(env))); err != nil {
	// 	log.Warningf("Failed building debugher for %s : %s", assert, err)
	// }

	//dump opcode in trace level
	log.Tracef("%s", runtimeFilter.Disassemble())

	output, err = expr.Run(runtimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"results": p.TestData}))
	if err != nil {
		log.Warningf("running : %s", expression)
		log.Warningf("runtime error : %s", err)
		return output, errors.Wrapf(err, "while running expression %s", expression)
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

func (p *ParserAssert) AutoGenParserAssert() string {
	//attempt to autogen parser asserts
	var ret string
	for stage, parsers := range *p.TestData {
		for parser, presults := range parsers {
			for pidx, result := range presults {
				ret += fmt.Sprintf(`results["%s"]["%s"][%d].Success == %t`+"\n", stage, parser, pidx, result.Success)

				if !result.Success {
					continue
				}
				for pkey, pval := range result.Evt.Parsed {
					if pval == "" {
						continue
					}
					ret += fmt.Sprintf(`results["%s"]["%s"][%d].Evt.Parsed["%s"] == "%s"`+"\n", stage, parser, pidx, pkey, strings.ReplaceAll(pval, "\"", "\\\""))
				}
				for mkey, mval := range result.Evt.Meta {
					if mval == "" {
						continue
					}
					ret += fmt.Sprintf(`results["%s"]["%s"][%d].Evt.Meta["%s"] == "%s"`+"\n", stage, parser, pidx, mkey, strings.ReplaceAll(mval, "\"", "\\\""))
				}
				for ekey, eval := range result.Evt.Enriched {
					if eval == "" {
						continue
					}
					ret += fmt.Sprintf(`results["%s"]["%s"][%d].Evt.Enriched["%s"] == "%s"`+"\n", stage, parser, pidx, ekey, strings.ReplaceAll(eval, "\"", "\\\""))
				}
			}
		}
	}
	return ret
}

func LoadParserDump(filepath string) (*ParserResults, error) {
	var pdump *ParserResults

	dumpData, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer dumpData.Close()

	results, err := ioutil.ReadAll(dumpData)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(results, pdump); err != nil {
		return nil, err
	}
	return pdump, nil
}

func DumpParserTree(parser_results ParserResults) error {
	//note : we can use line -> time as the unique identifier (of acquisition)

	state := make(map[time.Time]map[string]map[string]bool, 0)
	assoc := make(map[time.Time]string, 0)

	for stage, parsers := range parser_results {
		log.Printf("stage : %s", stage)
		for parser, results := range parsers {
			log.Printf("parser : %s", parser)
			for _, parser_res := range results {
				evt := parser_res.Evt
				if _, ok := state[evt.Line.Time]; !ok {
					state[evt.Line.Time] = make(map[string]map[string]bool)
					assoc[evt.Line.Time] = evt.Line.Raw
				}
				if _, ok := state[evt.Line.Time][stage]; !ok {
					state[evt.Line.Time][stage] = make(map[string]bool)
				}
				state[evt.Line.Time][stage][parser] = parser_res.Success
			}
		}
	}

	//get each line
	for tstamp, rawstr := range assoc {
		fmt.Printf("line:%s\n", rawstr)
		skeys := make([]string, 0, len(state[tstamp]))
		for k := range state[tstamp] {
			skeys = append(skeys, k)
		}
		sort.Strings(skeys)
		//iterate stage
		for idx, stage := range skeys {
			parsers := state[tstamp][stage]

			sep := "├"
			presep := "|"
			if idx == len(skeys)-1 {
				sep = "└"
				presep = ""
			}
			fmt.Printf("\t%s %s\n", sep, stage)

			pkeys := make([]string, 0, len(parsers))
			for k := range parsers {
				pkeys = append(pkeys, k)
			}
			sort.Strings(pkeys)

			for idx, parser := range pkeys {
				res := parsers[parser]
				sep := "├"
				if idx == len(pkeys)-1 {
					sep = "└"
				}
				if res {
					fmt.Printf("\t%s\t%s %s %s\n", presep, sep, emoji.GreenCircle, parser)
				} else {
					fmt.Printf("\t%s\t%s %s %s\n", presep, sep, emoji.RedCircle, parser)

				}
			}
		}

	}
	return nil
}
