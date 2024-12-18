package parser

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type TestFile struct {
	Lines   []types.Event `yaml:"lines,omitempty"`
	Results []types.Event `yaml:"results,omitempty"`
}

var debug = false

func TestParser(t *testing.T) {
	debug = true

	log.SetLevel(log.InfoLevel)

	envSetting := os.Getenv("TEST_ONLY")

	pctx, ectx := prepTests(t)

	// Init the enricher
	if envSetting != "" {
		if err := testOneParser(t, pctx, ectx, envSetting, nil); err != nil {
			t.Fatalf("Test '%s' failed : %s", envSetting, err)
		}
	} else {
		fds, err := os.ReadDir("./tests/")
		if err != nil {
			t.Fatalf("Unable to read test directory : %s", err)
		}

		for _, fd := range fds {
			if !fd.IsDir() {
				continue
			}

			fname := "./tests/" + fd.Name()
			log.Infof("Running test on %s", fname)

			if err := testOneParser(t, pctx, ectx, fname, nil); err != nil {
				t.Fatalf("Test '%s' failed : %s", fname, err)
			}
		}
	}
}

func BenchmarkParser(t *testing.B) {
	log.Printf("start bench !!!!")

	debug = false

	log.SetLevel(log.ErrorLevel)

	pctx, ectx := prepTests(t)

	envSetting := os.Getenv("TEST_ONLY")

	if envSetting != "" {
		err := testOneParser(t, pctx, ectx, envSetting, t)
		require.NoError(t, err, "Test '%s' failed", envSetting)
	} else {
		fds, err := os.ReadDir("./tests/")
		require.NoError(t, err, "Unable to read test directory")

		for _, fd := range fds {
			if !fd.IsDir() {
				continue
			}

			fname := "./tests/" + fd.Name()
			log.Infof("Running test on %s", fname)

			err := testOneParser(t, pctx, ectx, fname, t)
			require.NoError(t, err, "Test '%s' failed", fname)
		}
	}
}

func testOneParser(t require.TestingT, pctx *UnixParserCtx, ectx EnricherCtx, dir string, b *testing.B) error {
	var (
		err            error
		pnodes         []Node
		parser_configs []Stagefile
	)

	log.Warningf("testing %s", dir)

	parser_cfg_file := fmt.Sprintf("%s/parsers.yaml", dir)

	cfg, err := os.ReadFile(parser_cfg_file)
	if err != nil {
		return fmt.Errorf("failed opening %s: %w", parser_cfg_file, err)
	}

	tmpl, err := template.New("test").Parse(string(cfg))
	if err != nil {
		return fmt.Errorf("failed to parse template %s: %w", cfg, err)
	}

	var out bytes.Buffer

	err = tmpl.Execute(&out, map[string]string{"TestDirectory": dir})
	if err != nil {
		panic(err)
	}

	if err = yaml.UnmarshalStrict(out.Bytes(), &parser_configs); err != nil {
		return fmt.Errorf("failed to parse %s: %w", parser_cfg_file, err)
	}

	pnodes, err = LoadStages(parser_configs, pctx, ectx)
	if err != nil {
		return fmt.Errorf("unable to load parser config: %w", err)
	}

	// TBD: Load post overflows
	// func testFile(t *testing.T, file string, pctx UnixParserCtx, nodes []Node) bool {
	parser_test_file := fmt.Sprintf("%s/test.yaml", dir)
	tests := loadTestFile(t, parser_test_file)
	count := 1

	if b != nil {
		count = b.N
		b.ResetTimer()
	}

	for range count {
		if !testFile(t, tests, *pctx, pnodes) {
			return errors.New("test failed")
		}
	}

	return nil
}

// prepTests is going to do the initialisation of parser : it's going to load enrichment plugins and load the patterns. This is done here so that we don't redo it for each test
func prepTests(t require.TestingT) (*UnixParserCtx, EnricherCtx) {
	var (
		err  error
		pctx *UnixParserCtx
		ectx EnricherCtx
	)

	err = exprhelpers.Init(nil)
	require.NoError(t, err, "exprhelpers init failed")

	// Load enrichment
	datadir := "./test_data/"

	err = exprhelpers.GeoIPInit(datadir)
	require.NoError(t, err, "geoip init failed")

	ectx, err = Loadplugin()
	require.NoError(t, err, "load plugin failed")

	log.Printf("Loaded -> %+v", ectx)

	// Load the parser patterns
	cfgdir := "../../config/"

	/* this should be refactored to 2 lines :p */
	// Init the parser
	pctx, err = Init(map[string]interface{}{"patterns": cfgdir + string("/patterns/"), "data": "./tests/"})
	require.NoError(t, err, "parser init failed")

	return pctx, ectx
}

func loadTestFile(t require.TestingT, file string) []TestFile {
	yamlFile, err := os.Open(file)
	require.NoError(t, err, "failed to open test file")

	dec := yaml.NewDecoder(yamlFile)
	dec.SetStrict(true)

	var testSet []TestFile

	for {
		tf := TestFile{}

		err := dec.Decode(&tf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			require.NoError(t, err, "failed to load testfile '%s'", file)

			return nil
		}

		testSet = append(testSet, tf)
	}

	return testSet
}

func matchEvent(expected types.Event, out types.Event, debug bool) ([]string, bool) {
	var retInfo []string

	valid := false
	expectMaps := []map[string]string{expected.Parsed, expected.Meta, expected.Enriched}
	outMaps := []map[string]string{out.Parsed, out.Meta, out.Enriched}
	outLabels := []string{"Parsed", "Meta", "Enriched"}

	// allow to check as well for stage and processed flags
	if expected.Stage != "" {
		if expected.Stage != out.Stage {
			if debug {
				retInfo = append(retInfo, fmt.Sprintf("mismatch stage %s != %s", expected.Stage, out.Stage))
			}

			goto checkFinished
		}

		valid = true

		if debug {
			retInfo = append(retInfo, fmt.Sprintf("ok stage %s == %s", expected.Stage, out.Stage))
		}
	}

	if expected.Process != out.Process {
		if debug {
			retInfo = append(retInfo, fmt.Sprintf("mismatch process %t != %t", expected.Process, out.Process))
		}

		goto checkFinished
	}

	valid = true

	if debug {
		retInfo = append(retInfo, fmt.Sprintf("ok process %t == %t", expected.Process, out.Process))
	}

	if expected.Whitelisted != out.Whitelisted {
		if debug {
			retInfo = append(retInfo, fmt.Sprintf("mismatch whitelist %t != %t", expected.Whitelisted, out.Whitelisted))
		}

		goto checkFinished
	}

	if debug {
		retInfo = append(retInfo, fmt.Sprintf("ok whitelist %t == %t", expected.Whitelisted, out.Whitelisted))
	}

	valid = true

	for mapIdx := range len(expectMaps) {
		for expKey, expVal := range expectMaps[mapIdx] {
			outVal, ok := outMaps[mapIdx][expKey]
			if !ok {
				if debug {
					retInfo = append(retInfo, fmt.Sprintf("missing entry %s[%s]", outLabels[mapIdx], expKey))
				}

				valid = false

				goto checkFinished
			}

			if outVal != expVal { // ok entry
				if debug {
					retInfo = append(retInfo, fmt.Sprintf("mismatch %s[%s] %s != %s", outLabels[mapIdx], expKey, expVal, outVal))
				}

				valid = false

				goto checkFinished
			}

			if debug {
				retInfo = append(retInfo, fmt.Sprintf("ok %s[%s] %s == %s", outLabels[mapIdx], expKey, expVal, outVal))
			}

			valid = true
		}
	}
checkFinished:
	if valid {
		if debug {
			retInfo = append(retInfo, fmt.Sprintf("OK ! \n\t%s", strings.Join(retInfo, "\n\t")))
		}
	} else {
		if debug {
			retInfo = append(retInfo, fmt.Sprintf("KO ! \n\t%s", strings.Join(retInfo, "\n\t")))
		}
	}

	return retInfo, valid
}

func testSubSet(testSet TestFile, pctx UnixParserCtx, nodes []Node) (bool, error) {
	var results []types.Event

	for _, in := range testSet.Lines {
		out, err := Parse(pctx, in, nodes)
		if err != nil {
			log.Errorf("Failed to process %s : %v", spew.Sdump(in), err)
		}
		// log.Infof("Parser output : %s", spew.Sdump(out))
		results = append(results, out)
	}

	log.Infof("parsed %d lines", len(testSet.Lines))
	log.Infof("got %d results", len(results))

	/*
		check the results we got against the expected ones
		only the keys of the expected part are checked against result
	*/
	if len(testSet.Results) == 0 && len(results) == 0 {
		return false, errors.New("no tests, no results")
	}

reCheck:
	failinfo := []string{}

	for ridx, result := range results {
		for eidx, expected := range testSet.Results {
			explain, match := matchEvent(expected, result, debug)
			if match {
				log.Infof("expected %d/%d matches result %d/%d", eidx, len(testSet.Results), ridx, len(results))

				if len(explain) > 0 {
					log.Printf("-> %s", explain[len(explain)-1])
				}
				// don't do this at home : delete current element from list and redo
				results[len(results)-1], results[ridx] = results[ridx], results[len(results)-1]
				results = results[:len(results)-1]

				testSet.Results[len(testSet.Results)-1], testSet.Results[eidx] = testSet.Results[eidx], testSet.Results[len(testSet.Results)-1]
				testSet.Results = testSet.Results[:len(testSet.Results)-1]

				goto reCheck
			}

			failinfo = append(failinfo, explain...)
		}
	}

	if len(results) > 0 {
		log.Printf("Errors : %s", strings.Join(failinfo, " / "))
		return false, fmt.Errorf("leftover results : %+v", results)
	}

	if len(testSet.Results) > 0 {
		log.Printf("Errors : %s", strings.Join(failinfo, " / "))
		return false, fmt.Errorf("leftover expected results : %+v", testSet.Results)
	}

	return true, nil
}

func testFile(t require.TestingT, testSet []TestFile, pctx UnixParserCtx, nodes []Node) bool {
	log.Warning("Going to process one test set")

	for _, tf := range testSet {
		// func testSubSet(testSet TestFile, pctx UnixParserCtx, nodes []Node) (bool, error) {
		testOk, err := testSubSet(tf, pctx, nodes)
		require.NoError(t, err, "test failed")
		assert.True(t, testOk, "failed test: %+v", tf)
	}

	return true
}

/*THIS IS ONLY PRESENT TO BE ABLE TO GENERATE DOCUMENTATION OF EXISTING PATTERNS*/
type Pair struct {
	Key   string
	Value string
}

type PairList []Pair

func (p PairList) Len() int           { return len(p) }
func (p PairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p PairList) Less(i, j int) bool { return len(p[i].Value) < len(p[j].Value) }

func TestGeneratePatternsDoc(t *testing.T) {
	if os.Getenv("GO_WANT_TEST_DOC") != "1" {
		return
	}

	pctx, err := Init(map[string]interface{}{"patterns": "../../config/patterns/", "data": "./tests/"})
	require.NoError(t, err, "unable to load patterns")

	log.Infof("-> %s", spew.Sdump(pctx))
	/*don't judge me, we do it for the users*/
	p := make(PairList, len(pctx.Grok.Patterns))

	i := 0

	for key, val := range pctx.Grok.Patterns {
		p[i] = Pair{key, val}
		p[i].Value = strings.ReplaceAll(p[i].Value, "{%{", "\\{\\%\\{")
		i++
	}

	sort.Sort(p)

	f, err := os.OpenFile("./patterns-documentation.md", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("failed to open : %s", err)
	}

	if _, err := f.WriteString("# Patterns documentation\n\n"); err != nil {
		t.Fatal("failed to write to file")
	}

	if _, err := f.WriteString("You will find here a generated documentation of all the patterns loaded by crowdsec.\n"); err != nil {
		t.Fatal("failed to write to file")
	}

	if _, err := f.WriteString("They are sorted by pattern length, and are meant to be used in parsers, in the form %{PATTERN_NAME}.\n"); err != nil {
		t.Fatal("failed to write to file")
	}

	if _, err := f.WriteString("\n\n"); err != nil {
		t.Fatal("failed to write to file")
	}

	for _, k := range p {
		if _, err := fmt.Fprintf(f, "## %s\n\nPattern :\n```\n%s\n```\n\n", k.Key, k.Value); err != nil {
			t.Fatal("failed to write to file")
		}

		fmt.Printf("%v\t%v\n", k.Key, k.Value)
	}

	if _, err := f.WriteString("\n"); err != nil {
		t.Fatal("failed to write to file")
	}

	if _, err := f.WriteString("# Documentation generation\n"); err != nil {
		t.Fatal("failed to write to file")
	}

	if _, err := f.WriteString("This documentation is generated by `pkg/parser` : `GO_WANT_TEST_DOC=1 go test -run TestGeneratePatternsDoc`\n"); err != nil {
		t.Fatal("failed to write to file")
	}

	f.Close()
}
