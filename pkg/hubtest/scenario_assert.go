package hubtest

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/expr-lang/expr"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/dumps"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type ScenarioAssert struct {
	File              string
	AutoGenAssert     bool
	AutoGenAssertData string
	NbAssert          int
	Fails             []AssertFail
	Success           bool
	TestData          *BucketResults
	PourData          *dumps.BucketPourInfo
}

type BucketResults []types.Event

func NewScenarioAssert(file string) *ScenarioAssert {
	ScenarioAssert := &ScenarioAssert{
		File:          file,
		NbAssert:      0,
		Success:       false,
		Fails:         make([]AssertFail, 0),
		AutoGenAssert: false,
		TestData:      &BucketResults{},
		PourData:      &dumps.BucketPourInfo{},
	}

	return ScenarioAssert
}

func (s *ScenarioAssert) AutoGenFromFile(filename string) (string, error) {
	err := s.LoadTest(filename, "")
	if err != nil {
		return "", err
	}

	ret := s.AutoGenScenarioAssert()

	return ret, nil
}

func (s *ScenarioAssert) LoadTest(filename string, bucketpour string) error {
	bucketDump, err := LoadScenarioDump(filename)
	if err != nil {
		return fmt.Errorf("loading scenario dump file '%s': %w", filename, err)
	}

	s.TestData = bucketDump

	if bucketpour != "" {
		pourDump, err := dumps.LoadBucketPourDump(bucketpour)
		if err != nil {
			return fmt.Errorf("loading bucket pour dump file '%s': %w", filename, err)
		}

		s.PourData = pourDump
	}

	return nil
}

func (s *ScenarioAssert) AssertFile(testFile string) error {
	file, err := os.Open(s.File)
	if err != nil {
		return errors.New("failed to open")
	}

	if err := s.LoadTest(testFile, ""); err != nil {
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

		ok, err := s.Run(scanner.Text())
		if err != nil {
			return fmt.Errorf("unable to run assert '%s': %w", scanner.Text(), err)
		}

		s.NbAssert++

		if !ok {
			log.Debugf("%s is FALSE", scanner.Text())
			failedAssert := &AssertFail{
				File:       s.File,
				Line:       nbLine,
				Expression: scanner.Text(),
				Debug:      make(map[string]string),
			}

			match := variableRE.FindStringSubmatch(scanner.Text())

			if len(match) == 0 {
				log.Infof("Couldn't get variable of line '%s'", scanner.Text())
				continue
			}

			variable := match[1]

			result, err := s.EvalExpression(variable)
			if err != nil {
				log.Errorf("unable to evaluate variable '%s': %s", variable, err)
				continue
			}

			failedAssert.Debug[variable] = result
			s.Fails = append(s.Fails, *failedAssert)

			continue
		}
		// fmt.Printf(" %s '%s'\n", emoji.GreenSquare, scanner.Text())
	}

	file.Close()

	if s.NbAssert == 0 {
		assertData, err := s.AutoGenFromFile(testFile)
		if err != nil {
			return fmt.Errorf("couldn't generate assertion: %w", err)
		}

		s.AutoGenAssertData = assertData
		s.AutoGenAssert = true
	}

	if len(s.Fails) == 0 {
		s.Success = true
	}

	return nil
}

func (s *ScenarioAssert) RunExpression(expression string) (any, error) {
	// debug doesn't make much sense with the ability to evaluate "on the fly"
	// var debugFilter *exprhelpers.ExprDebugger
	var output any

	logger := log.WithField("file", s.File)

	env := map[string]any{"results": *s.TestData}
	opts := exprhelpers.GetExprOptions(env)
	opts = append(opts, expr.Function("basename", basename, new(func (string) string)))

	expression = basenameShim(expression)

	runtimeFilter, err := expr.Compile(expression, opts...)
	if err != nil {
		return nil, err
	}
	// if debugFilter, err = exprhelpers.NewDebugger(assert, expr.Env(env)); err != nil {
	// 	logger.Warningf("Failed building debugher for %s : %s", assert, err)
	// }

	// dump opcode in trace level
	logger.Tracef("%s", runtimeFilter.Disassemble())

	output, err = expr.Run(runtimeFilter, map[string]any{"results": *s.TestData})
	if err != nil {
		logger.Warningf("running : %s", expression)
		logger.Warningf("runtime error : %s", err)

		return nil, fmt.Errorf("while running expression %s: %w", expression, err)
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
	// attempt to autogen scenario asserts
	ret := fmt.Sprintf(`len(results) == %d`+"\n", len(*s.TestData))

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
				if meta.Key == "datasource_path" {
					ret += fmt.Sprintf(`basename(results[%d].Overflow.Alert.Events[%d].GetMeta("%s")) == "%s"`+"\n", eventIndex, evtIndex, meta.Key, Escape(filepath.Base(meta.Value)))
				} else {
					ret += fmt.Sprintf(`results[%d].Overflow.Alert.Events[%d].GetMeta("%s") == "%s"`+"\n", eventIndex, evtIndex, meta.Key, Escape(meta.Value))
				}
			}
		}

		ret += fmt.Sprintf(`results[%d].Overflow.Alert.GetScenario() == "%s"`+"\n", eventIndex, *event.Overflow.Alert.Scenario)
		ret += fmt.Sprintf(`results[%d].Overflow.Alert.Remediation == %t`+"\n", eventIndex, event.Overflow.Alert.Remediation)
		ret += fmt.Sprintf(`results[%d].Overflow.Alert.GetEventsCount() == %d`+"\n", eventIndex, *event.Overflow.Alert.EventsCount)
	}

	return ret
}

func (b BucketResults) Len() int {
	return len(b)
}

func (b BucketResults) Less(i, j int) bool {
	return b[i].Overflow.Alert.GetScenario()+strings.Join(b[i].Overflow.GetSources(), "@") > b[j].Overflow.Alert.GetScenario()+strings.Join(b[j].Overflow.GetSources(), "@")
}

func (b BucketResults) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

func LoadScenarioDump(filepath string) (*BucketResults, error) {
	dumpData, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer dumpData.Close()

	results, err := io.ReadAll(dumpData)
	if err != nil {
		return nil, err
	}

	var bucketDump BucketResults

	if err := yaml.Unmarshal(results, &bucketDump); err != nil {
		return nil, err
	}

	sort.Sort(bucketDump)

	return &bucketDump, nil
}
