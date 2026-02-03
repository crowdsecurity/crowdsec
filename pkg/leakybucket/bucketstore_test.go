package leakybucket

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type TestFile struct {
	Lines   []pipeline.Event `yaml:"lines,omitempty"`
	Results []pipeline.Event `yaml:"results,omitempty"`
}

func TestBucket(t *testing.T) {
	t.Parallel()

	var envSetting = os.Getenv("TEST_ONLY")

	testdata := "./testdata"

	hubCfg := &csconfig.LocalHubCfg{
		HubDir:         filepath.Join(testdata, "hub"),
		HubIndexFile:   filepath.Join(testdata, "hub", "index.json"),
		InstallDataDir: testdata,
	}

	hub, err := cwhub.NewHub(hubCfg, nil)
	require.NoError(t, err)

	err = hub.Load()
	require.NoError(t, err)

	err = exprhelpers.Init(nil)
	require.NoError(t, err)

	if envSetting != "" {
		t.Run(filepath.Base(envSetting), func(t *testing.T) {
			t.Parallel()
			testOneBucket(t, hub, envSetting)
		})
		return
	}

	fds, err := os.ReadDir(testdata)
	require.NoError(t, err)

	for _, fd := range fds {
		if fd.Name() == "hub" {
			continue
		}

		fname := filepath.Join(testdata, fd.Name())
		log.Infof("Running test on %s", fname)

		t.Run(fd.Name(), func(t *testing.T) {
			t.Parallel()
			testOneBucket(t, hub, fname)
		})
	}
}

func testOneBucket(t *testing.T, hub *cwhub.Hub, dir string) {
	var (
		holders []BucketFactory

		stagefiles []byte
		stagecfg   string
		stages     []parser.Stagefile
		err        error
	)

	bucketStore := NewBucketStore()

	// load the scenarios
	stagecfg = dir + "/scenarios.yaml"
	stagefiles, err = os.ReadFile(stagecfg)
	require.NoError(t, err)

	tmpl, err := template.New("test").Parse(string(stagefiles))
	require.NoError(t, err)

	var out bytes.Buffer

	err = tmpl.Execute(&out, map[string]string{"TestDirectory": dir})
	require.NoError(t, err)

	err = yaml.UnmarshalStrict(out.Bytes(), &stages)
	require.NoError(t, err)

	scenarios := []*cwhub.Item{}

	for _, x := range stages {
		// XXX: LoadBuckets should take an interface, BucketProvider ScenarioProvider or w/e
		item := &cwhub.Item{
			Name: x.Filename,
			State: cwhub.ItemState{
				LocalVersion: "",
				LocalPath:    x.Filename,
				LocalHash:    "",
			},
		}

		scenarios = append(scenarios, item)
	}

	cscfg := &csconfig.CrowdsecServiceCfg{}

	holders, response, err := LoadBuckets(cscfg, hub, scenarios, bucketStore, false)
	require.NoError(t, err)

	testFile(t, filepath.Join(dir, "test.json"), holders, response, bucketStore)
}

func testFile(t *testing.T, file string, holders []BucketFactory, response chan pipeline.Event, bucketStore *BucketStore) {
	var results []pipeline.Event

	yamlFile, err := os.Open(file)
	require.NoError(t, err)
	t.Cleanup(func() { _ = yamlFile.Close() })

	dec := json.NewDecoder(yamlFile)
	dec.DisallowUnknownFields()

	// dec.SetStrict(true)
	tf := TestFile{}
	err = dec.Decode(&tf)
	require.NotErrorIs(t, err, io.EOF)
	require.NoError(t, err, "failed to decode test file %q", file)

	var extra json.RawMessage
	err = dec.Decode(&extra)
	require.ErrorIs(t, err, io.EOF, "test file %q has trailing content after the first JSON value", file)

	var latest_ts time.Time
	ctx := t.Context()
	for _, in := range tf.Lines {
		// just to avoid any race during ingestion of funny scenarios
		time.Sleep(50 * time.Millisecond)
		var ts time.Time

		err := ts.UnmarshalText([]byte(in.MarshaledTime))
		require.NoError(t, err)

		if latest_ts.IsZero() {
			latest_ts = ts
		} else if ts.After(latest_ts) {
			latest_ts = ts
		}

		in.ExpectMode = pipeline.TIMEMACHINE
		log.Infof("Buckets input : %s", spew.Sdump(in))

		ok, err := PourItemToHolders(ctx, in, holders, bucketStore, nil)
		require.NoError(t, err)

		if !ok {
			log.Warning("Event wasn't poured")
		}
	}
	log.Warning("Done pouring !")

	time.Sleep(1 * time.Second)

	// Read results from chan
POLL_AGAIN:
	fails := 0
	for fails < 2 {
		select {
		case ret := <-response:
			log.Warning("got one result")
			results = append(results, ret)
			if ret.Overflow.Reprocess {
				log.Errorf("Overflow being reprocessed.")
				ok, err := PourItemToHolders(ctx, ret, holders, bucketStore, nil)
				require.NoError(t, err)
				if !ok {
					log.Warning("Event wasn't poured")
				}
				goto POLL_AGAIN
			}
			fails = 0
		default:
			log.Warning("no more results")
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
			log.Warning("Test is successful")
			return
		}
		require.Len(t, results, len(tf.Results))
	checkresultsloop:
		for eidx, out := range results {
			for ridx, expected := range tf.Results {
				log.Tracef("Checking next expected result.")

				// empty overflow
				if out.Overflow.Alert == nil && expected.Overflow.Alert == nil {
					// match stuff
				} else {
					if out.Overflow.Alert == nil || expected.Overflow.Alert == nil {
						log.Info("Here ?")
						continue
					}

					// Scenario
					if *out.Overflow.Alert.Scenario != *expected.Overflow.Alert.Scenario {
						log.Errorf("(scenario) %v != %v", *out.Overflow.Alert.Scenario, *expected.Overflow.Alert.Scenario)
						continue
					}
					log.Infof("(scenario) %v == %v", *out.Overflow.Alert.Scenario, *expected.Overflow.Alert.Scenario)

					// EventsCount
					if *out.Overflow.Alert.EventsCount != *expected.Overflow.Alert.EventsCount {
						log.Errorf("(EventsCount) %d != %d", *out.Overflow.Alert.EventsCount, *expected.Overflow.Alert.EventsCount)
						continue
					}
					log.Infof("(EventsCount) %d == %d", *out.Overflow.Alert.EventsCount, *expected.Overflow.Alert.EventsCount)

					// Sources
					if !reflect.DeepEqual(out.Overflow.Sources, expected.Overflow.Sources) {
						log.Errorf("(Sources %s != %s)", spew.Sdump(out.Overflow.Sources), spew.Sdump(expected.Overflow.Sources))
						continue
					}
					log.Infof("(Sources: %s == %s)", spew.Sdump(out.Overflow.Sources), spew.Sdump(expected.Overflow.Sources))
				}
				// Events
				// if !reflect.DeepEqual(out.Overflow.Alert.Events, expected.Overflow.Alert.Events) {
				// 	log.Errorf("(Events %s != %s)", spew.Sdump(out.Overflow.Alert.Events), spew.Sdump(expected.Overflow.Alert.Events))
				// 	valid = false
				// 	continue
				// } else {
				// 	log.Infof("(Events: %s == %s)", spew.Sdump(out.Overflow.Alert.Events), spew.Sdump(expected.Overflow.Alert.Events))
				// }

				// CheckFailed:

				log.Warningf("The test is valid, remove entry %d from expects, and %d from t.Results", eidx, ridx)
				// don't do this at home : delete current element from list and redo
				results[eidx] = results[len(results)-1]
				results = results[:len(results)-1]
				tf.Results[ridx] = tf.Results[len(tf.Results)-1]
				tf.Results = tf.Results[:len(tf.Results)-1]
				goto checkresultsloop
			}
		}
		if len(results) != 0 && len(tf.Results) != 0 {
			require.Failf(t, "mismatching entries left",
				"we got: %s\nwe expected: %s", spew.Sdump(results), spew.Sdump(tf.Results))
		}
		log.Warning("entry valid at end of loop")
	}
}
