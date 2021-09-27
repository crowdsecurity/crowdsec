package cstest

type ScenarioAssert struct {
	File              string
	AutoGenAssert     bool
	AutoGenAssertData string
	NbAssert          int
	Fails             []string
	Success           bool
}

func NewScenarioAssert(file string) (*ScenarioAssert, error) {
	ScenarioAssert := &ScenarioAssert{
		File:          file,
		NbAssert:      0,
		Success:       false,
		Fails:         make([]string, 0),
		AutoGenAssert: false,
	}
	return ScenarioAssert, nil
}

/*

func (p *ScenarioAssert) AutoGenFromFile(filename string) (string, error) {
	pdump, err := LoadParserDump(filename)
	if err != nil {
		return "", err
	}
	ret := autogenScenarioAsserts(pdump)
	return ret, nil
}

func (p *ScenarioAssert) AssertFile(testFile string) error {
	file, err := os.Open(p.File)

	if err != nil {
		return fmt.Errorf("failed to open")
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	pdump, err := LoadParserDump(testFile)
	if err != nil {
		return fmt.Errorf("loading parser dump file: %+v", err)
	}

	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		ok, err := runOneScenarioAssert(scanner.Text(), pdump)
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

func runOneScenarioAssert(assert string, results ParserResults) (bool, error) {
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

func autogenScenarioAsserts(parserResults ParserResults) string {
	//attempt to autogen parser asserts
	var ret string
	for stage, parsers := range parserResults {
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
			}
		}
	}
	return ret
}

func LoadParserDump(filepath string) (map[string]map[string][]parserResult, error) {
	var pdump ParserResults

	data_fd, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer data_fd.Close()
	//umarshal full gruik
	results, err := ioutil.ReadAll(data_fd)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(results, &pdump); err != nil {
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
*/
