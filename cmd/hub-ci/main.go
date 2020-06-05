package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

var acquisTomb tomb.Tomb
var testDir string

var AllResults []LineParseResult
var AllExpected []LineParseResult

type LineParseResult struct {
	Line          string
	ParserResults map[string]map[string]types.Event
}

//cleanForMatch : cleanup results from items that might change every run
func cleanForMatch(in map[string]map[string]types.Event) map[string]map[string]types.Event {
	for stage, val := range in {
		for parser, evt := range val {
			evt.Line.Time = time.Time{}
			in[stage][parser] = evt
		}
	}
	return in
}

func parseMatchLine(event types.Event, parserCTX *parser.UnixParserCtx, parserNodes []parser.Node) bool {
	oneResult := LineParseResult{}
	h := sha256.New()

	if event.Line.Raw == "" {
		log.Warningf("discarding empty line")
		return true
	}
	h.Write([]byte(event.Line.Raw))
	log.Printf("processing '%s'", event.Line.Raw)

	//parse
	parsed, err := parser.Parse(*parserCTX, event, parserNodes)
	if err != nil {
		log.Fatalf("failed parsing : %v\n", err)
	}

	if !parsed.Process {
		log.Warningf("Unparsed: %s", parsed.Line.Raw)
	}
	//marshal current result
	oneResult.Line = parsed.Line.Raw
	//we need to clean Line's timestamp
	oneResult.ParserResults = cleanForMatch(parser.StageParseCache)
	/*
	** we are using cmp's feature to match structures.
	** because of the way marshal/unmarshal works we want to make nil == empty
	 */
	// This option handles slices and maps of any type.
	alwaysEqual := cmp.Comparer(func(_, _ interface{}) bool { return true })
	opt := cmp.FilterValues(func(x, y interface{}) bool {
		vx, vy := reflect.ValueOf(x), reflect.ValueOf(y)
		return (vx.IsValid() && vy.IsValid() && vx.Type() == vy.Type()) &&
			(vx.Kind() == reflect.Slice || vx.Kind() == reflect.Map) &&
			(vx.Len() == 0 && vy.Len() == 0)
	}, alwaysEqual)

	/*
		Iterate over the list of expected results and try to find back
	*/
	AllResults = append(AllResults, oneResult)
	matched := false
	for idx, candidate := range AllExpected {
		//not our line
		if candidate.Line != event.Line.Raw {
			continue
		}
		if cmp.Equal(candidate, oneResult, opt) {
			matched = true
			//we go an exact match
			log.Printf("Found exact match (idx:%d)", idx)
			//cleanup
			AllExpected = append(AllExpected[:idx], AllExpected[idx+1:]...)
		} else {
			log.Printf("Mismatch for line :")
			log.Printf("%s", cmp.Diff(candidate, oneResult, opt))
		}
		break
	}
	if !matched && len(AllExpected) != 0 {
		log.Fatalf("Result is not in the %d expected results", len(AllExpected))
	}
	return matched
}

func main() {
	var (
		err            error
		p              parser.UnixParser
		parserCTX      *parser.UnixParserCtx
		parserNodes    []parser.Node = make([]parser.Node, 0)
		acquisitionCTX *acquisition.FileAcquisCtx
		cConfig        *csconfig.CrowdSec
	)
	inputLineChan := make(chan types.Event)
	log.SetLevel(log.InfoLevel)
	cConfig = csconfig.NewCrowdSecConfig()

	test_dir := os.Args[1]

	cConfig.AcquisitionFile = test_dir + "/acquis.yaml"
	log.Printf("Setting acquis source to %s", cConfig.AcquisitionFile)
	/* load base regexps for two grok parsers */
	parserCTX, err = p.Init(map[string]interface{}{"patterns": cConfig.ConfigFolder + string("/patterns/"), "data": cConfig.DataFolder})
	if err != nil {
		log.Errorf("failed to initialize parser : %v", err)
		return
	}
	/* Load enrichers */
	log.Infof("Loading enrich plugins")
	parserPlugins, err := parser.Loadplugin(cConfig.DataFolder)
	if err != nil {
		log.Errorf("Failed to load plugin geoip : %v", err)
	}
	parser.ECTX = append(parser.ECTX, parserPlugins)
	//load parsers
	log.Infof("Loading parsers")
	parserNodes, err = parser.LoadStageDir(cConfig.ConfigFolder+"/parsers/", parserCTX)
	if err != nil {
		log.Fatalf("failed to load parser config : %v", err)
	}

	//Init the acqusition : from cli or from acquis.yaml file
	acquisitionCTX, err = acquisition.LoadAcquisitionConfig(cConfig)
	if err != nil {
		log.Fatalf("Failed to start acquisition : %s", err)
	}

	// if len(acquisitionCTX.Files) != 1 {
	// 	log.Fatalf("only one file per dir")
	// }

	//load the expected results
	ExpectedPresent := false
	expectedResultsFile := test_dir + "/results.yaml"
	expected_bytes, err := ioutil.ReadFile(expectedResultsFile)
	if err != nil {
		log.Warningf("no results in %s, will dump data instead!", test_dir)
	} else {
		if err := json.Unmarshal(expected_bytes, &AllExpected); err != nil {
			log.Fatalf("file %s can't be unmarshaled : %s", expectedResultsFile, err)
		} else {
			ExpectedPresent = true
		}
	}

	//start reading in the background
	acquisition.AcquisStartReading(acquisitionCTX, inputLineChan, &acquisTomb)

	//Try to load the results file
	//expected_bytes, err := ioutil.ReadFile(test_dir)

	go func() {
		log.Printf("starting to process stuff!")
		parser.ParseDump = true
		for event := range inputLineChan {
			if !parseMatchLine(event, parserCTX, parserNodes) {
				fmt.Printf("while parsing:\n%s\n", event.Line.Raw)
				//log.Fatalf("mismatch test")
			}
		}
	}()

	if err := acquisTomb.Wait(); err != nil {
		log.Warningf("acquisition returned error : %s", err)
	}

	time.Sleep(1 * time.Second)
	/*now let's check the results*/

	//there was no data present, just dump
	if !ExpectedPresent {
		log.Warningf("No expected results loaded, dump.")
		dump_bytes, err := json.MarshalIndent(AllResults, "", " ")
		if err != nil {
			log.Fatalf("failed to marshal results : %s", err)
		}
		if err := ioutil.WriteFile(expectedResultsFile, dump_bytes, 0644); err != nil {
			log.Fatalf("failed to dump data to %s : %s", expectedResultsFile, err)
		}
	} else {
		if len(AllExpected) > 0 {
			log.Errorf("Left-over results in expected : %d", len(AllExpected))
		}
	}
	log.Infof("tests are finished.")
}
