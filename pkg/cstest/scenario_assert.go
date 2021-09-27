package cstest

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type ScenarioAssert struct {
	File              string
	AutoGenAssert     bool
	AutoGenAssertData string
	NbAssert          int
	Fails             []string
	Success           bool
	TestData          *BucketResults
}

type BucketResults []types.Event

func NewScenarioAssert(file string) (*ScenarioAssert, error) {
	ScenarioAssert := &ScenarioAssert{
		File:          file,
		NbAssert:      0,
		Success:       false,
		Fails:         make([]string, 0),
		AutoGenAssert: false,
		TestData:      &BucketResults{},
	}
	return ScenarioAssert, nil
}

func (s *ScenarioAssert) AutoGenFromFile(filename string) (string, error) {
	err := s.LoadTest(filename)
	if err != nil {
		return "", err
	}
	ret := s.AutoGenScenarioAssert()
	return ret, nil
}

func (s *ScenarioAssert) LoadTest(filename string) error {
	var err error
	bucketDump, err := LoadScenarioDump(filename)
	if err != nil {
		return fmt.Errorf("loading scenario dump file '%s': %+v", filename, err)
	}
	s.TestData = bucketDump
	return nil
}

func (s *ScenarioAssert) AssertFile(testFile string) error {
	file, err := os.Open(s.File)

	if err != nil {
		return fmt.Errorf("failed to open")
	}

	if err := s.LoadTest(testFile); err != nil {
		return fmt.Errorf("unable to load parser dump file '%s': %s", testFile, err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		ok, err := s.Run(scanner.Text())
		if err != nil {
			return fmt.Errorf("unable to run assert '%s': %+v", scanner.Text(), err)
		}
		s.NbAssert += 1
		if !ok {
			log.Debugf("%s is FALSE", scanner.Text())
			//fmt.SPrintf(" %s '%s'\n", emoji.RedSquare, scanner.Text())
			s.Fails = append(s.Fails, scanner.Text())
			continue
		}
		//fmt.Printf(" %s '%s'\n", emoji.GreenSquare, scanner.Text())

	}
	file.Close()
	if s.NbAssert == 0 {
		assertData, err := s.AutoGenFromFile(testFile)
		if err != nil {
			return fmt.Errorf("couldn't generate assertion: %s", err.Error())
		}
		s.AutoGenAssertData = assertData
		s.AutoGenAssert = true
	}

	if len(s.Fails) == 0 {
		s.Success = true
	}

	return nil
}

func (s *ScenarioAssert) RunExpression(expression string) (interface{}, error) {
	var err error
	//debug doesn't make much sense with the ability to evaluate "on the fly"
	//var debugFilter *exprhelpers.ExprDebugger
	var runtimeFilter *vm.Program
	var output interface{}

	env := map[string]interface{}{"results": *s.TestData}

	if runtimeFilter, err = expr.Compile(expression, expr.Env(exprhelpers.GetExprEnv(env))); err != nil {
		return output, err
	}
	// if debugFilter, err = exprhelpers.NewDebugger(assert, expr.Env(exprhelpers.GetExprEnv(env))); err != nil {
	// 	log.Warningf("Failed building debugher for %s : %s", assert, err)
	// }

	//dump opcode in trace level
	log.Tracef("%s", runtimeFilter.Disassemble())

	output, err = expr.Run(runtimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"results": *s.TestData}))
	if err != nil {
		log.Warningf("running : %s", expression)
		log.Warningf("runtime error : %s", err)
		return output, errors.Wrapf(err, "while running expression %s", expression)
	}
	return output, nil
}

func (s *ScenarioAssert) EvalExpression(expression string) (string, error) {
	output, err := s.RunExpression(expression)
	if err != nil {
		return "", err
	}
	ret, err := yaml.Marshal(output)
	if err != nil {
		return "", err
	}
	return string(ret), nil
}

func (s *ScenarioAssert) Run(assert string) (bool, error) {
	output, err := s.RunExpression(assert)
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

func (s *ScenarioAssert) AutoGenScenarioAssert() string {
	//attempt to autogen parser asserts
	var ret string
	for eventIndex, event := range *s.TestData {
		for ipSrc, source := range event.Overflow.Sources {
			ret += fmt.Sprintf(`"%s" in results[%d].Overflow.GetSources()`+"\n", ipSrc, eventIndex)
			ret += fmt.Sprintf(`results[%d].Overflow.Sources["%s"].IP == "%s"`+"\n", eventIndex, ipSrc, source.IP)
			ret += fmt.Sprintf(`results[%d].Overflow.Sources["%s"].Range == "%s"`+"\n", eventIndex, ipSrc, source.Range)
			ret += fmt.Sprintf(`results[%d].Overflow.Sources["%s"].GetScope() == "%s"`+"\n", eventIndex, ipSrc, *source.Scope)
			ret += fmt.Sprintf(`results[%d].Overflow.Sources["%s"].GetValue() == "%s"`+"\n", eventIndex, ipSrc, *source.Value)
		}
		for evtIndex, evt := range event.Overflow.Alert.Events {
			for _, meta := range evt.Meta {
				ret += fmt.Sprintf(`results[%d].Overflow.Alert.Events[%d].GetMeta("%s") == "%s"`+"\n", eventIndex, evtIndex, meta.Key, meta.Value)
			}
		}
		ret += fmt.Sprintf(`results[%d].Overflow.Alert.GetScenario() == "%s"`+"\n", eventIndex, *event.Overflow.Alert.Scenario)
		ret += fmt.Sprintf(`results[%d].Overflow.Alert.Remediation == %t`+"\n", eventIndex, *&event.Overflow.Alert.Remediation)
		ret += fmt.Sprintf(`results[%d].Overflow.Alert.GetEventsCount() == %d`+"\n", eventIndex, *event.Overflow.Alert.EventsCount)
	}
	return ret
}

func LoadScenarioDump(filepath string) (*BucketResults, error) {
	var bucketDump BucketResults

	dumpData, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer dumpData.Close()

	results, err := ioutil.ReadAll(dumpData)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(results, &bucketDump); err != nil {
		return nil, err
	}
	return &bucketDump, nil
}
