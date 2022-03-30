package parser

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type TestFile struct {
	Lines   []types.Event `yaml:"lines,omitempty"`
	Results []types.Event `yaml:"results,omitempty"`
}

var debug bool = false

func TestParser(t *testing.T) {
	debug = true
	log.SetLevel(log.InfoLevel)
	var envSetting = os.Getenv("TEST_ONLY")
	pctx, ectx, err := prepTests()
	if err != nil {
		t.Fatalf("failed to load env : %s", err)
	}
	//Init the enricher
	if envSetting != "" {
		if err := testOneParser(pctx, ectx, envSetting, nil); err != nil {
			t.Fatalf("Test '%s' failed : %s", envSetting, err)
		}
	} else {
		fds, err := ioutil.ReadDir("./tests/")
		if err != nil {
			t.Fatalf("Unable to read test directory : %s", err)
		}
		for _, fd := range fds {
			if !fd.IsDir() {
				continue
			}
			fname := "./tests/" + fd.Name()
			log.Infof("Running test on %s", fname)
			if err := testOneParser(pctx, ectx, fname, nil); err != nil {
				t.Fatalf("Test '%s' failed : %s", fname, err)
			}
		}
	}

}

func BenchmarkParser(t *testing.B) {
	log.Printf("start bench !!!!")
	debug = false
	log.SetLevel(log.ErrorLevel)
	pctx, ectx, err := prepTests()
	if err != nil {
		t.Fatalf("failed to load env : %s", err)
	}
	var envSetting = os.Getenv("TEST_ONLY")

	if envSetting != "" {
		if err := testOneParser(pctx, ectx, envSetting, t); err != nil {
			t.Fatalf("Test '%s' failed : %s", envSetting, err)
		}
	} else {
		fds, err := ioutil.ReadDir("./tests/")
		if err != nil {
			t.Fatalf("Unable to read test directory : %s", err)
		}
		for _, fd := range fds {
			if !fd.IsDir() {
				continue
			}
			fname := "./tests/" + fd.Name()
			log.Infof("Running test on %s", fname)
			if err := testOneParser(pctx, ectx, fname, t); err != nil {
				t.Fatalf("Test '%s' failed : %s", fname, err)
			}
		}
	}
}

func testOneParser(pctx *UnixParserCtx, ectx EnricherCtx, dir string, b *testing.B) error {

	var (
		err    error
		pnodes []Node

		parser_configs []Stagefile
	)
	log.Warningf("testing %s", dir)
	parser_cfg_file := fmt.Sprintf("%s/parsers.yaml", dir)
	cfg, err := ioutil.ReadFile(parser_cfg_file)
	if err != nil {
		return fmt.Errorf("failed opening %s : %s", parser_cfg_file, err)
	}
	tmpl, err := template.New("test").Parse(string(cfg))
	if err != nil {
		return fmt.Errorf("failed to parse template %s : %s", cfg, err)
	}
	var out bytes.Buffer
	err = tmpl.Execute(&out, map[string]string{"TestDirectory": dir})
	if err != nil {
		panic(err)
	}
	if err := yaml.UnmarshalStrict(out.Bytes(), &parser_configs); err != nil {
		return fmt.Errorf("failed unmarshaling %s : %s", parser_cfg_file, err)
	}

	pnodes, err = LoadStages(parser_configs, pctx, ectx)
	if err != nil {
		return fmt.Errorf("unable to load parser config : %s", err)
	}

	//TBD: Load post overflows
	//func testFile(t *testing.T, file string, pctx UnixParserCtx, nodes []Node) bool {
	parser_test_file := fmt.Sprintf("%s/test.yaml", dir)
	tests := loadTestFile(parser_test_file)
	count := 1
	if b != nil {
		count = b.N
		b.ResetTimer()
	}
	for n := 0; n < count; n++ {
		if testFile(tests, *pctx, pnodes) != true {
			return fmt.Errorf("test failed !")
		}
	}
	return nil
}

//prepTests is going to do the initialisation of parser : it's going to load enrichment plugins and load the patterns. This is done here so that we don't redo it for each test
func prepTests() (*UnixParserCtx, EnricherCtx, error) {
	var (
		err  error
		pctx *UnixParserCtx
		ectx EnricherCtx
	)

	err = exprhelpers.Init()
	if err != nil {
		log.Fatalf("exprhelpers init failed: %s", err)
	}

	//Load enrichment
	datadir := "./test_data/"
	ectx, err = Loadplugin(datadir)
	if err != nil {
		log.Fatalf("failed to load plugin geoip : %v", err)
	}
	log.Printf("Loaded -> %+v", ectx)

	//Load the parser patterns
	cfgdir := "../../config/"

	/* this should be refactored to 2 lines :p */
	// Init the parser
	pctx, err = Init(map[string]interface{}{"patterns": cfgdir + string("/patterns/"), "data": "./tests/"})
	if err != nil {
		return nil, ectx, fmt.Errorf("failed to initialize parser : %v", err)
	}
	return pctx, ectx, nil
}

func loadTestFile(file string) []TestFile {
	yamlFile, err := os.Open(file)
	if err != nil {
		log.Fatalf("yamlFile.Get err   #%v ", err)
	}
	dec := yaml.NewDecoder(yamlFile)
	dec.SetStrict(true)
	var testSet []TestFile
	for {
		tf := TestFile{}
		err := dec.Decode(&tf)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("Failed to load testfile '%s' yaml error : %v", file, err)
			return nil
		}
		testSet = append(testSet, tf)
	}
	return testSet
}

func matchEvent(expected types.Event, out types.Event, debug bool) ([]string, bool) {
	var retInfo []string
	var valid bool = false
	expectMaps := []map[string]string{expected.Parsed, expected.Meta, expected.Enriched}
	outMaps := []map[string]string{out.Parsed, out.Meta, out.Enriched}
	outLabels := []string{"Parsed", "Meta", "Enriched"}

	//allow to check as well for stage and processed flags
	if expected.Stage != "" {
		if expected.Stage != out.Stage {
			if debug {
				retInfo = append(retInfo, fmt.Sprintf("mismatch stage %s != %s", expected.Stage, out.Stage))
			}
			goto checkFinished
		} else {
			valid = true
			if debug {
				retInfo = append(retInfo, fmt.Sprintf("ok stage %s == %s", expected.Stage, out.Stage))
			}
		}
	}

	if expected.Process != out.Process {
		if debug {
			retInfo = append(retInfo, fmt.Sprintf("mismatch process %t != %t", expected.Process, out.Process))
		}
		goto checkFinished
	} else {
		valid = true
		if debug {
			retInfo = append(retInfo, fmt.Sprintf("ok process %t == %t", expected.Process, out.Process))
		}
	}

	if expected.Whitelisted != out.Whitelisted {
		if debug {
			retInfo = append(retInfo, fmt.Sprintf("mismatch whitelist %t != %t", expected.Whitelisted, out.Whitelisted))
		}
		goto checkFinished
	} else {
		if debug {
			retInfo = append(retInfo, fmt.Sprintf("ok whitelist %t == %t", expected.Whitelisted, out.Whitelisted))
		}
		valid = true
	}

	for mapIdx := 0; mapIdx < len(expectMaps); mapIdx++ {
		for expKey, expVal := range expectMaps[mapIdx] {
			if outVal, ok := outMaps[mapIdx][expKey]; ok {
				if outVal == expVal { //ok entry
					if debug {
						retInfo = append(retInfo, fmt.Sprintf("ok %s[%s] %s == %s", outLabels[mapIdx], expKey, expVal, outVal))
					}
					valid = true
				} else { //mismatch entry
					if debug {
						retInfo = append(retInfo, fmt.Sprintf("mismatch %s[%s] %s != %s", outLabels[mapIdx], expKey, expVal, outVal))
					}
					goto checkFinished
				}
			} else { //missing entry
				if debug {
					retInfo = append(retInfo, fmt.Sprintf("missing entry %s[%s]", outLabels[mapIdx], expKey))
				}
				valid = false
				goto checkFinished
			}
		}
	}
checkFinished:
	if valid {
		if debug {
			retInfo = append(retInfo, fmt.Sprintf("OK ! %s", strings.Join(retInfo, "/")))
		}
	} else {
		if debug {
			retInfo = append(retInfo, fmt.Sprintf("KO ! %s", strings.Join(retInfo, "/")))
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
		//log.Infof("Parser output : %s", spew.Sdump(out))
		results = append(results, out)
	}
	log.Infof("parsed %d lines", len(testSet.Lines))
	log.Infof("got %d results", len(results))

	/*
		check the results we got against the expected ones
		only the keys of the expected part are checked against result
	*/
	if len(testSet.Results) == 0 && len(results) == 0 {
		log.Fatalf("No results, no tests, abort.")
		return false, fmt.Errorf("no tests, no results")
	}

reCheck:
	failinfo := []string{}
	for ridx, result := range results {
		for eidx, expected := range testSet.Results {
			explain, match := matchEvent(expected, result, debug)
			if match == true {
				log.Infof("expected %d/%d matches result %d/%d", eidx, len(testSet.Results), ridx, len(results))
				if len(explain) > 0 {
					log.Printf("-> %s", explain[len(explain)-1])
				}
				//don't do this at home : delete current element from list and redo
				results[len(results)-1], results[ridx] = results[ridx], results[len(results)-1]
				results = results[:len(results)-1]

				testSet.Results[len(testSet.Results)-1], testSet.Results[eidx] = testSet.Results[eidx], testSet.Results[len(testSet.Results)-1]
				testSet.Results = testSet.Results[:len(testSet.Results)-1]

				goto reCheck
			} else {
				failinfo = append(failinfo, explain...)
			}
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

func testFile(testSet []TestFile, pctx UnixParserCtx, nodes []Node) bool {
	log.Warningf("Going to process one test set")
	for _, tf := range testSet {
		//func testSubSet(testSet TestFile, pctx UnixParserCtx, nodes []Node) (bool, error) {
		testOk, err := testSubSet(tf, pctx, nodes)
		if err != nil {
			log.Fatalf("test failed : %s", err)
		}
		if !testOk {
			log.Fatalf("failed test : %+v", tf)
		}
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
	if err != nil {
		t.Fatalf("unable to load patterns : %s", err)
	}
	log.Infof("-> %s", spew.Sdump(pctx))
	/*don't judge me, we do it for the users*/
	p := make(PairList, len(pctx.Grok))

	i := 0
	for key, val := range pctx.Grok {
		p[i] = Pair{key, val}
		p[i].Value = strings.Replace(p[i].Value, "{%{", "\\{\\%\\{", -1)
		i++
	}
	sort.Sort(p)

	f, err := os.OpenFile("./patterns-documentation.md", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
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
		if _, err := f.WriteString(fmt.Sprintf("## %s\n\nPattern :\n```\n%s\n```\n\n", k.Key, k.Value)); err != nil {
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
