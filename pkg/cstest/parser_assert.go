package cstest

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/enescakir/emoji"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	diff "github.com/r3labs/diff/v2"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
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
	TestData          *ParserResults
}

type ParserResult struct {
	Evt     types.Event
	Success bool
}
type ParserResults map[string]map[string][]ParserResult

func NewParserAssert(file string) *ParserAssert {

	ParserAssert := &ParserAssert{
		File:          file,
		NbAssert:      0,
		Success:       false,
		Fails:         make([]AssertFail, 0),
		AutoGenAssert: false,
		TestData:      &ParserResults{},
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
	nbLine := 0
	for scanner.Scan() {
		nbLine += 1
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
			failedAssert := &AssertFail{
				File:       p.File,
				Line:       nbLine,
				Expression: scanner.Text(),
				Debug:      make(map[string]string),
			}
			variableRE := regexp.MustCompile(`(?P<variable>[^  =]+) == .*`)
			match := variableRE.FindStringSubmatch(scanner.Text())
			if len(match) == 0 {
				log.Infof("Couldn't get variable of line '%s'", scanner.Text())
			}
			variable := match[1]
			result, err := p.EvalExpression(variable)
			if err != nil {
				log.Errorf("unable to evaluate variable '%s': %s", variable, err)
				continue
			}
			failedAssert.Debug[variable] = result
			p.Fails = append(p.Fails, *failedAssert)
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

	env := map[string]interface{}{"results": *p.TestData}

	if runtimeFilter, err = expr.Compile(expression, expr.Env(exprhelpers.GetExprEnv(env))); err != nil {
		return output, err
	}

	//dump opcode in trace level
	log.Tracef("%s", runtimeFilter.Disassemble())

	output, err = expr.Run(runtimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"results": *p.TestData}))
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

func Escape(val string) string {
	val = strings.ReplaceAll(val, `\`, `\\`)
	val = strings.ReplaceAll(val, `"`, `\"`)
	return val
}

func (p *ParserAssert) AutoGenParserAssert() string {
	//attempt to autogen parser asserts
	var ret string

	//sort map keys for consistent ordre
	var stages []string
	for stage := range *p.TestData {
		stages = append(stages, stage)
	}
	sort.Strings(stages)
	ret += fmt.Sprintf("len(results) == %d\n", len(*p.TestData))
	for _, stage := range stages {
		parsers := (*p.TestData)[stage]
		//sort map keys for consistent ordre
		var pnames []string
		for pname := range parsers {
			pnames = append(pnames, pname)
		}
		sort.Strings(pnames)
		for _, parser := range pnames {
			presults := parsers[parser]
			ret += fmt.Sprintf(`len(results["%s"]["%s"]) == %d`+"\n", stage, parser, len(presults))
			for pidx, result := range presults {
				ret += fmt.Sprintf(`results["%s"]["%s"][%d].Success == %t`+"\n", stage, parser, pidx, result.Success)

				if !result.Success {
					continue
				}
				for pkey, pval := range result.Evt.Parsed {
					if pval == "" {
						continue
					}
					ret += fmt.Sprintf(`results["%s"]["%s"][%d].Evt.Parsed["%s"] == "%s"`+"\n", stage, parser, pidx, pkey, Escape(pval))
				}
				for mkey, mval := range result.Evt.Meta {
					if mval == "" {
						continue
					}
					ret += fmt.Sprintf(`results["%s"]["%s"][%d].Evt.Meta["%s"] == "%s"`+"\n", stage, parser, pidx, mkey, Escape(mval))
				}
				for ekey, eval := range result.Evt.Enriched {
					if eval == "" {
						continue
					}
					ret += fmt.Sprintf(`results["%s"]["%s"][%d].Evt.Enriched["%s"] == "%s"`+"\n", stage, parser, pidx, ekey, Escape(eval))
				}
			}
		}
	}
	return ret
}

func LoadParserDump(filepath string) (*ParserResults, error) {
	var pdump ParserResults

	dumpData, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer dumpData.Close()

	results, err := ioutil.ReadAll(dumpData)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(results, &pdump); err != nil {
		return nil, err
	}
	return &pdump, nil
}

type DumpOpts struct {
	Details bool
	SkipOk  bool
}

func DumpTree(parser_results ParserResults, bucket_pour BucketPourInfo, opts DumpOpts) {
	//note : we can use line -> time as the unique identifier (of acquisition)

	state := make(map[time.Time]map[string]map[string]ParserResult)
	assoc := make(map[time.Time]string, 0)

	for stage, parsers := range parser_results {
		for parser, results := range parsers {
			for _, parser_res := range results {
				evt := parser_res.Evt
				if _, ok := state[evt.Line.Time]; !ok {
					state[evt.Line.Time] = make(map[string]map[string]ParserResult)
					assoc[evt.Line.Time] = evt.Line.Raw
				}
				if _, ok := state[evt.Line.Time][stage]; !ok {
					state[evt.Line.Time][stage] = make(map[string]ParserResult)
				}
				state[evt.Line.Time][stage][parser] = ParserResult{Evt: evt, Success: parser_res.Success}
			}

		}
	}

	for bname, evtlist := range bucket_pour {
		for _, evt := range evtlist {
			if evt.Line.Raw == "" {
				continue
			}
			//it might be bucket oveflow being reprocessed, skip this
			if _, ok := state[evt.Line.Time]; !ok {
				state[evt.Line.Time] = make(map[string]map[string]ParserResult)
				assoc[evt.Line.Time] = evt.Line.Raw
			}
			//there is a trick : to know if an event succesfully exit the parsers, we check if it reached the pour() phase
			//we thus use a fake stage "buckets" and a fake parser "OK" to know if it entered
			if _, ok := state[evt.Line.Time]["buckets"]; !ok {
				state[evt.Line.Time]["buckets"] = make(map[string]ParserResult)
			}
			state[evt.Line.Time]["buckets"][bname] = ParserResult{Success: true}
		}
	}
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	//get each line
	for tstamp, rawstr := range assoc {
		if opts.SkipOk {
			if _, ok := state[tstamp]["buckets"]["OK"]; ok {
				continue
			}
		}
		fmt.Printf("line: %s\n", rawstr)
		skeys := make([]string, 0, len(state[tstamp]))
		for k := range state[tstamp] {
			//there is a trick : to know if an event succesfully exit the parsers, we check if it reached the pour() phase
			//we thus use a fake stage "buckets" and a fake parser "OK" to know if it entered
			if k == "buckets" {
				continue
			}
			skeys = append(skeys, k)
		}
		sort.Strings(skeys)
		//iterate stage
		var prev_item types.Event

		for _, stage := range skeys {
			parsers := state[tstamp][stage]

			sep := "├"
			presep := "|"

			fmt.Printf("\t%s %s\n", sep, stage)

			pkeys := make([]string, 0, len(parsers))
			for k := range parsers {
				pkeys = append(pkeys, k)
			}
			sort.Strings(pkeys)

			for idx, parser := range pkeys {
				res := parsers[parser].Success
				sep := "├"
				if idx == len(pkeys)-1 {
					sep = "└"
				}
				created := 0
				updated := 0
				deleted := 0
				whitelisted := false
				changeStr := ""
				detailsDisplay := ""

				if res {
					if prev_item.Stage == "" {
						changeStr = "first_parser"
					} else {
						changelog, _ := diff.Diff(prev_item, parsers[parser].Evt)
						for _, change := range changelog {
							switch change.Type {
							case "create":
								created++
								detailsDisplay += fmt.Sprintf("\t%s\t\t%s %s evt.%s : %s\n", presep, sep, change.Type, strings.Join(change.Path, "."), green(change.To))
							case "update":
								detailsDisplay += fmt.Sprintf("\t%s\t\t%s %s evt.%s : %s -> %s\n", presep, sep, change.Type, strings.Join(change.Path, "."), change.From, yellow(change.To))
								if change.Path[0] == "Whitelisted" && change.To == true {
									whitelisted = true
								}
								updated++
							case "delete":
								deleted++
								detailsDisplay += fmt.Sprintf("\t%s\t\t%s %s evt.%s\n", presep, sep, change.Type, red(strings.Join(change.Path, ".")))
							}
						}
					}
					prev_item = parsers[parser].Evt
				}

				if created > 0 {
					changeStr += green(fmt.Sprintf("+%d", created))
				}
				if updated > 0 {
					if len(changeStr) > 0 {
						changeStr += " "
					}
					changeStr += yellow(fmt.Sprintf("~%d", updated))
				}
				if deleted > 0 {
					if len(changeStr) > 0 {
						changeStr += " "
					}
					changeStr += red(fmt.Sprintf("-%d", deleted))
				}
				if whitelisted {
					if len(changeStr) > 0 {
						changeStr += " "
					}
					changeStr += red("[whitelisted]")
				}
				if changeStr == "" {
					changeStr = yellow("unchanged")
				}
				if res {
					fmt.Printf("\t%s\t%s %s %s (%s)\n", presep, sep, emoji.GreenCircle, parser, changeStr)
					if opts.Details {
						fmt.Print(detailsDisplay)
					}
				} else {
					fmt.Printf("\t%s\t%s %s %s\n", presep, sep, emoji.RedCircle, parser)

				}
			}
		}
		sep := "└"
		if len(state[tstamp]["buckets"]) > 0 {
			sep = "├"
		}
		//did the event enter the bucket pour phase ?
		if _, ok := state[tstamp]["buckets"]["OK"]; ok {
			fmt.Printf("\t%s-------- parser success %s\n", sep, emoji.GreenCircle)
		} else {
			fmt.Printf("\t%s-------- parser failure %s\n", sep, emoji.RedCircle)
		}
		//now print bucket info
		if len(state[tstamp]["buckets"]) > 0 {
			fmt.Printf("\t├ Scenarios\n")
		}
		bnames := make([]string, 0, len(state[tstamp]["buckets"]))
		for k := range state[tstamp]["buckets"] {
			//there is a trick : to know if an event succesfully exit the parsers, we check if it reached the pour() phase
			//we thus use a fake stage "buckets" and a fake parser "OK" to know if it entered
			if k == "OK" {
				continue
			}
			bnames = append(bnames, k)
		}
		sort.Strings(bnames)
		for idx, bname := range bnames {
			sep := "├"
			if idx == len(bnames)-1 {
				sep = "└"
			}
			fmt.Printf("\t\t%s %s %s\n", sep, emoji.GreenCircle, bname)
		}
		fmt.Println()
	}
}
