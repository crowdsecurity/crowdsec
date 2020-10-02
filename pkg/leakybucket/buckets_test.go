package leakybucket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

type TestFile struct {
	Lines   []types.Event `yaml:"lines,omitempty"`
	Results []types.Event `yaml:"results,omitempty"`
}

func TestBucket(t *testing.T) {

	var envSetting = os.Getenv("TEST_ONLY")
	err := exprhelpers.Init()
	if err != nil {
		log.Fatalf("exprhelpers init failed: %s", err)
	}

	if envSetting != "" {
		if err := testOneBucket(t, envSetting); err != nil {
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
			if err := testOneBucket(t, fname); err != nil {
				t.Fatalf("Test '%s' failed : %s", fname, err)
			}
		}
	}
}

func testOneBucket(t *testing.T, dir string) error {

	var holders []BucketFactory

	var stagefiles []byte
	var stagecfg string
	var stages []parser.Stagefile
	var err error

	/*load the scenarios*/
	stagecfg = dir + "/scenarios.yaml"
	if stagefiles, err = ioutil.ReadFile(stagecfg); err != nil {
		t.Fatalf("Failed to load stage file %s : %s", stagecfg, err)
	}

	tmpl, err := template.New("test").Parse(string(stagefiles))
	if err != nil {
		return fmt.Errorf("failed to parse template %s : %s", stagefiles, err)
	}
	var out bytes.Buffer
	err = tmpl.Execute(&out, map[string]string{"TestDirectory": dir})
	if err != nil {
		panic(err)
	}
	if err := yaml.UnmarshalStrict(out.Bytes(), &stages); err != nil {
		log.Fatalf("failed unmarshaling %s : %s", stagecfg, err)
	}
	files := []string{}
	for _, x := range stages {
		files = append(files, x.Filename)
	}

	cscfg := &csconfig.CrowdsecServiceCfg{
		DataDir: "tests",
	}
	holders, response, err := LoadBuckets(cscfg, files)
	if err != nil {
		t.Fatalf("failed loading bucket : %s", err)
	}
	if !testFile(t, dir+"/test.json", dir+"/in-buckets_state.json", holders, response) {
		return fmt.Errorf("tests from %s failed", dir)
	}
	return nil
}

func testFile(t *testing.T, file string, bs string, holders []BucketFactory, response chan types.Event) bool {

	var results []types.Event
	var buckets *Buckets
	var dump bool

	buckets = NewBuckets()
	//should we restore
	if _, err := os.Stat(bs); err == nil {
		dump = true
		if err := LoadBucketsState(bs, buckets, holders); err != nil {
			t.Fatalf("Failed to load bucket state : %s", err)
		}
	}

	/* now we can load the test files */
	//process the yaml
	yamlFile, err := os.Open(file)
	if err != nil {
		t.Errorf("yamlFile.Get err   #%v ", err)
	}
	dec := json.NewDecoder(yamlFile)
	dec.DisallowUnknownFields()
	//dec.SetStrict(true)
	tf := TestFile{}
	err = dec.Decode(&tf)
	if err != nil {
		if err == io.EOF {
			log.Warningf("end of test file")
		} else {
			t.Errorf("Failed to load testfile '%s' yaml error : %v", file, err)
			return false
		}
	}
	var latest_ts time.Time
	for _, in := range tf.Lines {
		//just to avoid any race during ingestion of funny scenarios
		time.Sleep(50 * time.Millisecond)
		var ts time.Time
		if err := ts.UnmarshalText([]byte(in.MarshaledTime)); err != nil {
			t.Fatalf("Failed to unmarshal time from input event : %s", err)
		}
		if latest_ts.IsZero() {
			latest_ts = ts
		} else if ts.After(latest_ts) {
			latest_ts = ts
		}

		in.ExpectMode = TIMEMACHINE
		log.Infof("Buckets input : %s", spew.Sdump(in))
		ok, err := PourItemToHolders(in, holders, buckets)
		if err != nil {
			t.Fatalf("Failed to pour : %s", err)
		}
		if !ok {
			log.Warningf("Event wasn't poured")
		}
	}
	log.Warningf("Done pouring !")

	time.Sleep(1 * time.Second)

	//Read results from chan
POLL_AGAIN:
	fails := 0
	for fails < 2 {
		select {
		case ret := <-response:
			log.Warningf("got one result")
			results = append(results, ret)
			if ret.Overflow.Reprocess {
				log.Errorf("Overflow being reprocessed.")
				ok, err := PourItemToHolders(ret, holders, buckets)
				if err != nil {
					t.Fatalf("Failed to pour : %s", err)
				}
				if !ok {
					log.Warningf("Event wasn't poured")
				}
				goto POLL_AGAIN
			}
			fails = 0
		default:
			log.Warningf("no more results")
			time.Sleep(1 * time.Second)
			fails += 1
		}
	}
	log.Warningf("Got %d overflows from run", len(results))
	/*
		check the results we got against the expected ones
		only the keys of the expected part are checked against result
	*/
	var tmpFile string

	for {
		if len(tf.Results) == 0 && len(results) == 0 {
			log.Warningf("Test is successfull")
			if dump {
				if tmpFile, err = DumpBucketsStateAt(latest_ts, ".", buckets); err != nil {
					t.Fatalf("Failed dumping bucket state : %s", err)
				}
				log.Infof("dumped bucket to %s", tmpFile)
			}
			return true
		} else {
			log.Warningf("%d results to check against %d expected results", len(results), len(tf.Results))
			if len(tf.Results) != len(results) {
				if dump {
					if tmpFile, err = DumpBucketsStateAt(latest_ts, ".", buckets); err != nil {
						t.Fatalf("Failed dumping bucket state : %s", err)
					}
					log.Infof("dumped bucket to %s", tmpFile)

				}
				log.Errorf("results / expected count doesn't match results = %d / expected = %d", len(results), len(tf.Results))
				return false
			}
		}
	checkresultsloop:
		for eidx, out := range results {
			for ridx, expected := range tf.Results {

				log.Tracef("Checking next expected result.")

				//empty overflow
				if out.Overflow.Alert == nil && expected.Overflow.Alert == nil {
					//match stuff
				} else {
					if out.Overflow.Alert == nil || expected.Overflow.Alert == nil {
						log.Printf("Here ?")
						continue
					}
					//Scenario

					if *out.Overflow.Alert.Scenario != *expected.Overflow.Alert.Scenario {
						log.Errorf("(scenario) %v != %v", *out.Overflow.Alert.Scenario, *expected.Overflow.Alert.Scenario)
						continue
					} else {
						log.Infof("(scenario) %v == %v", *out.Overflow.Alert.Scenario, *expected.Overflow.Alert.Scenario)
					}
					//EventsCount
					if *out.Overflow.Alert.EventsCount != *expected.Overflow.Alert.EventsCount {
						log.Errorf("(EventsCount) %d != %d", *out.Overflow.Alert.EventsCount, *expected.Overflow.Alert.EventsCount)
						continue
					} else {
						log.Infof("(EventsCount) %d == %d", *out.Overflow.Alert.EventsCount, *expected.Overflow.Alert.EventsCount)
					}
					//Sources
					if !reflect.DeepEqual(out.Overflow.Sources, expected.Overflow.Sources) {
						log.Errorf("(Sources %s != %s)", spew.Sdump(out.Overflow.Sources), spew.Sdump(expected.Overflow.Sources))
						continue
					} else {
						log.Infof("(Sources: %s == %s)", spew.Sdump(out.Overflow.Sources), spew.Sdump(expected.Overflow.Sources))
					}

				}
				//Events
				// if !reflect.DeepEqual(out.Overflow.Alert.Events, expected.Overflow.Alert.Events) {
				// 	log.Errorf("(Events %s != %s)", spew.Sdump(out.Overflow.Alert.Events), spew.Sdump(expected.Overflow.Alert.Events))
				// 	valid = false
				// 	continue
				// } else {
				// 	log.Infof("(Events: %s == %s)", spew.Sdump(out.Overflow.Alert.Events), spew.Sdump(expected.Overflow.Alert.Events))
				// }

				//CheckFailed:

				log.Warningf("The test is valid, remove entry %d from expects, and %d from t.Results", eidx, ridx)
				//don't do this at home : delete current element from list and redo
				results[eidx] = results[len(results)-1]
				results = results[:len(results)-1]
				tf.Results[ridx] = tf.Results[len(tf.Results)-1]
				tf.Results = tf.Results[:len(tf.Results)-1]
				goto checkresultsloop
			}
		}
		if len(results) != 0 && len(tf.Results) != 0 {
			log.Errorf("mismatching entries left")
			log.Errorf("we got: %s", spew.Sdump(results))
			log.Errorf("we expected: %s", spew.Sdump(tf.Results))
			return false
		} else {
			log.Warningf("entry valid at end of loop")
		}
	}
	return false
}
