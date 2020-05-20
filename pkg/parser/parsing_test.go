package parser

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type TestFile struct {
	Lines   []types.Event `yaml:"lines,omitempty"`
	Results []types.Event `yaml:"results,omitempty"`
}

func TestParser(t *testing.T) {

	var envSetting = os.Getenv("TEST_ONLY")

	if envSetting != "" {
		if err := testOneParser(t, envSetting); err != nil {
			t.Fatalf("Test '%s' failed : %s", envSetting, err)
		}
	} else {
		fds, err := ioutil.ReadDir("./tests/")
		if err != nil {
			t.Fatalf("Unable to read test directory : %s", err)
		}
		for _, fd := range fds {
			fname := "./tests/" + fd.Name()
			log.Infof("Running test on %s", fname)
			if err := testOneParser(t, fname); err != nil {
				t.Fatalf("Test '%s' failed : %s", fname, err)
			}
		}
	}

}

func testOneParser(t *testing.T, dir string) error {
	var p UnixParser
	var pctx *UnixParserCtx
	var err error
	var pnodes []Node

	log.SetLevel(log.DebugLevel)

	datadir := "../../data/"
	cfgdir := "../../config/"

	/* this should be refactored to 2 lines :p */
	// Init the parser
	pctx, err = p.Init(map[string]interface{}{"patterns": cfgdir + string("/patterns/")})
	if err != nil {
		return fmt.Errorf("failed to initialize parser : %v", err)
	}
	//Init the enricher
	pplugins, err := Loadplugin(datadir)
	if err != nil {
		return fmt.Errorf("failed to load plugin geoip : %v", err)
	}
	ECTX = append(ECTX, pplugins)
	log.Debugf("Geoip ctx : %v", ECTX)
	//Load the parser configuration
	var parser_configs []Stagefile
	//TBD var po_parser_configs []Stagefile

	parser_cfg_file := fmt.Sprintf("%s/parsers.yaml", dir)
	b, err := ioutil.ReadFile(parser_cfg_file)
	if err != nil {
		return fmt.Errorf("failed opening %s : %s", parser_cfg_file, err)
	}
	tmpl, err := template.New("test").Parse(string(b))
	if err != nil {
		return fmt.Errorf("failed to parse template %s : %s", b, err)
	}
	var out bytes.Buffer
	err = tmpl.Execute(&out, map[string]string{"TestDirectory": dir})
	if err != nil {
		panic(err)
	}
	if err := yaml.UnmarshalStrict(out.Bytes(), &parser_configs); err != nil {
		return fmt.Errorf("failed unmarshaling %s : %s", parser_cfg_file, err)
	}

	pnodes, err = LoadStages(parser_configs, pctx)
	if err != nil {
		return fmt.Errorf("unable to load parser config : %s", err)
	}

	//TBD: Load post overflows
	//func testFile(t *testing.T, file string, pctx UnixParserCtx, nodes []Node) bool {
	parser_test_file := fmt.Sprintf("%s/test.yaml", dir)
	if testFile(t, parser_test_file, *pctx, pnodes) != true {
		return fmt.Errorf("test failed !")
	}
	return nil
}

func testFile(t *testing.T, file string, pctx UnixParserCtx, nodes []Node) bool {

	var expects []types.Event

	/* now we can load the test files */
	//process the yaml
	yamlFile, err := os.Open(file)
	if err != nil {
		t.Errorf("yamlFile.Get err   #%v ", err)
	}
	dec := yaml.NewDecoder(yamlFile)
	dec.SetStrict(true)
	for {
		tf := TestFile{}
		err := dec.Decode(&tf)
		if err != nil {
			if err == io.EOF {
				log.Warningf("end of test file")
				break
			}
			t.Errorf("Failed to load testfile '%s' yaml error : %v", file, err)
			return false
		}
		for _, in := range tf.Lines {
			log.Debugf("Parser input : %s", spew.Sdump(in))
			out, err := Parse(pctx, in, nodes)
			if err != nil {
				log.Errorf("Failed to process %s : %v", spew.Sdump(in), err)
			}
			log.Debugf("Parser output : %s", spew.Sdump(out))
			expects = append(expects, out)
		}
		/*
			check the results we got against the expected ones
			only the keys of the expected part are checked against result
		*/
		if len(tf.Results) == 0 && len(expects) == 0 {
			t.Errorf("No results, no tests, abort.")
			return false

			//return false
		}
	redo:
		if len(tf.Results) == 0 && len(expects) == 0 {
			log.Warningf("Test is successfull")
			return true
		} else {
			log.Warningf("%d results to check against %d expected results", len(expects), len(tf.Results))
		}
		for eidx, out := range expects {
			for ridx, expected := range tf.Results {

				log.Debugf("Checking next expected result.")
				valid := true

				//allow to check as well for stage and processed flags
				if expected.Stage != "" {
					if expected.Stage != out.Stage {
						log.Infof("out/expected mismatch 'Stage' value : (got) '%s' != (expected) '%s'", out.Stage, expected.Stage)
						valid = false
						goto CheckFailed
					} else {
						log.Infof("Stage == '%s'", expected.Stage)
					}
				}
				if expected.Process != out.Process {
					log.Infof("out/expected mismatch 'Process' value : (got) '%t' != (expected) '%t'", out.Process, expected.Process)
					valid = false
					goto CheckFailed
				} else {
					log.Infof("Process == '%t'", out.Process)
				}

				if expected.Whitelisted != out.Whitelisted {
					log.Infof("out/expected mismatch 'Whitelisted' value : (got) '%t' != (expected) '%t'", out.Whitelisted, expected.Whitelisted)
					valid = false
					goto CheckFailed
				} else {
					log.Infof("Whitelisted == '%t'", out.Whitelisted)
				}

				for k, v := range expected.Parsed {
					/*check 3 main dicts : event, enriched, meta */
					if val, ok := out.Parsed[k]; ok {
						if val != v {
							log.Infof("out/expected mismatch 'event' entry [%s] : (got) '%s' != (expected) '%s'", k, val, v)
							valid = false
							goto CheckFailed
						} else {
							log.Infof(".Parsed[%s] == '%s'", k, val)
						}
					} else {
						log.Infof("missing event entry [%s] in expected : %v", k, out.Parsed)
						valid = false
						goto CheckFailed
					}
				}

				for k, v := range expected.Meta {
					/*check 3 main dicts : event, enriched, meta */
					if val, ok := out.Meta[k]; ok {
						if val != v {
							log.Infof("out/expected mismatch 'meta' entry [%s] : (got) '%s' != (expected) '%s'", k, val, v)
							valid = false
							goto CheckFailed
						} else {
							log.Infof("Meta[%s] == '%s'", k, val)
						}
					} else {
						log.Warningf("missing meta entry [%s] in expected", k)
						valid = false
						goto CheckFailed
					}
				}

				for k, v := range expected.Enriched {
					/*check 3 main dicts : event, enriched, meta */
					if val, ok := out.Enriched[k]; ok {
						if val != v {
							log.Infof("out/expected mismatch 'Enriched' entry [%s] : (got) '%s' != (expected) '%s'", k, val, v)
							valid = false
							goto CheckFailed
						} else {
							log.Infof("Enriched[%s] == '%s'", k, val)
						}
					} else {
						log.Warningf("missing enriched entry [%s] in expected", k)
						valid = false
						goto CheckFailed
					}
				}

			CheckFailed:

				if valid {
					//log.Infof("Found result [%s], skip", spew.Sdump(tf.Results[ridx]))
					log.Warningf("The test is valid, remove entry %d from expects, and %d from t.Results", eidx, ridx)
					//don't do this at home : delete current element from list and redo
					expects[eidx] = expects[len(expects)-1]
					expects = expects[:len(expects)-1]
					tf.Results[ridx] = tf.Results[len(tf.Results)-1]
					tf.Results = tf.Results[:len(tf.Results)-1]
					goto redo
				}

			}

		}

	}
	t.Errorf("failed test")
	return false
}
