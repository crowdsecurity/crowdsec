package leakybucket

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"os"
	"testing"
	"time"

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

var (
	configDir = "./data"
)

func TestBucket(t *testing.T) {

	var envSetting = os.Getenv("TEST_ONLY")

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
	holders, response, err := LoadBuckets(files, configDir)
	if err != nil {
		t.Fatalf("failed loading bucket : %s", err)
	}
	if !testFile(t, dir+"/test.yaml", dir+"/in-buckets_state.json", holders, response) {
		t.Fatalf("the test failed")
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
	dec := yaml.NewDecoder(yamlFile)
	dec.SetStrict(true)
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
		log.Debugf("Buckets input : %s", spew.Sdump(in))
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
				log.Debugf("Overflow being reprocessed.")
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

	for {
		if len(tf.Results) == 0 && len(results) == 0 {
			log.Warningf("Test is successfull")
			if dump {
				if err := DumpBucketsStateAt(bs+".new", latest_ts, buckets); err != nil {
					t.Fatalf("Failed dumping bucket state : %s", err)
				}
			}
			return true
		} else {
			log.Warningf("%d results to check against %d expected results", len(results), len(tf.Results))
			if len(tf.Results) != len(results) {
				if dump {
					if err := DumpBucketsStateAt(bs+".new", latest_ts, buckets); err != nil {
						t.Fatalf("Failed dumping bucket state : %s", err)
					}
				}
				log.Errorf("results / expected count doesn't match results = %d / expected = %d", len(results), len(tf.Results))
				return false
			}
		}
		var valid bool
	checkresultsloop:
		for eidx, out := range results {
			for ridx, expected := range tf.Results {

				log.Debugf("Checking next expected result.")
				valid = true

				log.Infof("go %s", spew.Sdump(out))
				//Scenario
				if out.Overflow.Scenario != expected.Overflow.Scenario {
					log.Errorf("(scenario) %s != %s", out.Overflow.Scenario, expected.Overflow.Scenario)
					valid = false
					continue
				} else {
					log.Infof("(scenario) %s == %s", out.Overflow.Scenario, expected.Overflow.Scenario)
				}
				//Events_count
				if out.Overflow.Events_count != expected.Overflow.Events_count {
					log.Errorf("(Events_count) %d != %d", out.Overflow.Events_count, expected.Overflow.Events_count)
					valid = false
					continue
				} else {
					log.Infof("(Events_count) %d == %d", out.Overflow.Events_count, expected.Overflow.Events_count)
				}
				//Source_ip
				if out.Overflow.Source_ip != expected.Overflow.Source_ip {
					log.Errorf("(Source_ip) %s != %s", out.Overflow.Source_ip, expected.Overflow.Source_ip)
					valid = false
					continue
				} else {
					log.Infof("(Source_ip) %s == %s", out.Overflow.Source_ip, expected.Overflow.Source_ip)
				}

				//CheckFailed:

				if valid {
					log.Warningf("The test is valid, remove entry %d from expects, and %d from t.Results", eidx, ridx)
					//don't do this at home : delete current element from list and redo
					results[eidx] = results[len(results)-1]
					results = results[:len(results)-1]
					tf.Results[ridx] = tf.Results[len(tf.Results)-1]
					tf.Results = tf.Results[:len(tf.Results)-1]
					break checkresultsloop
				}
			}
		}
		if !valid {
			t.Fatalf("mismatching entries left")
		} else {
			log.Warningf("entry valid at end of loop")
		}
	}
	return false
}
