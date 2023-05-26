package parser

/*
 This file contains
 - the runtime parsing routines
*/

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"

	"strconv"

	"github.com/mohae/deepcopy"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/antonmedv/expr"
)

/* ok, this is kinda experimental, I don't know how bad of an idea it is .. */
func SetTargetByName(target string, value string, evt *types.Event) bool {

	if evt == nil {
		return false
	}

	//it's a hack, we do it for the user
	target = strings.TrimPrefix(target, "evt.")

	log.Debugf("setting target %s to %s", target, value)
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Runtime error while trying to set '%s': %+v", target, r)
			return
		}
	}()

	iter := reflect.ValueOf(evt).Elem()
	if (iter == reflect.Value{}) || iter.IsZero() {
		log.Tracef("event is nill")
		//event is nill
		return false
	}
	for _, f := range strings.Split(target, ".") {
		/*
		** According to current Event layout we only have to handle struct and map
		 */
		switch iter.Kind() {
		case reflect.Map:
			tmp := iter.MapIndex(reflect.ValueOf(f))
			/*if we're in a map and the field doesn't exist, the user wants to add it :) */
			if (tmp == reflect.Value{}) || tmp.IsZero() {
				log.Debugf("map entry is zero in '%s'", target)
			}
			iter.SetMapIndex(reflect.ValueOf(f), reflect.ValueOf(value))
			return true
		case reflect.Struct:
			tmp := iter.FieldByName(f)
			if !tmp.IsValid() {
				log.Debugf("'%s' is not a valid target because '%s' is not valid", target, f)
				return false
			}
			if tmp.Kind() == reflect.Ptr {
				tmp = reflect.Indirect(tmp)
			}
			iter = tmp
			//nolint: gosimple
			break
		case reflect.Ptr:
			tmp := iter.Elem()
			iter = reflect.Indirect(tmp.FieldByName(f))
		default:
			log.Errorf("unexpected type %s in '%s'", iter.Kind(), target)
			return false
		}
	}
	//now we should have the final member :)
	if !iter.CanSet() {
		log.Errorf("'%s' can't be set", target)
		return false
	}
	if iter.Kind() != reflect.String {
		log.Errorf("Expected string, got %v when handling '%s'", iter.Kind(), target)
		return false
	}
	iter.Set(reflect.ValueOf(value))
	return true
}

func printStaticTarget(static types.ExtraField) string {

	if static.Method != "" {
		return static.Method
	} else if static.Parsed != "" {
		return fmt.Sprintf(".Parsed[%s]", static.Parsed)
	} else if static.Meta != "" {
		return fmt.Sprintf(".Meta[%s]", static.Meta)
	} else if static.Enriched != "" {
		return fmt.Sprintf(".Enriched[%s]", static.Enriched)
	} else if static.TargetByName != "" {
		return static.TargetByName
	} else {
		return "?"
	}
}

func (n *Node) ProcessStatics(statics []types.ExtraField, event *types.Event) error {
	//we have a few cases :
	//(meta||key) + (static||reference||expr)
	var value string
	clog := n.Logger

	for _, static := range statics {
		value = ""
		if static.Value != "" {
			value = static.Value
		} else if static.RunTimeValue != nil {
			output, err := expr.Run(static.RunTimeValue, map[string]interface{}{"evt": event})
			if err != nil {
				clog.Warningf("failed to run RunTimeValue : %v", err)
				continue
			}
			switch out := output.(type) {
			case string:
				value = out
			case int:
				value = strconv.Itoa(out)
			case map[string]interface{}:
				clog.Warnf("Expression '%s' returned a map, please use ToJsonString() to convert it to string if you want to keep it as is, or refine your expression to extract a string", static.ExpValue)
			case []interface{}:
				clog.Warnf("Expression '%s' returned an array, please use ToJsonString() to convert it to string if you want to keep it as is, or refine your expression to extract a string", static.ExpValue)
			case nil:
				clog.Debugf("Expression '%s' returned nil, skipping", static.ExpValue)
			default:
				clog.Errorf("unexpected return type for RunTimeValue : %T", output)
				return errors.New("unexpected return type for RunTimeValue")
			}
		}

		if value == "" {
			//allow ParseDate to have empty input
			if static.Method != "ParseDate" {
				clog.Debugf("Empty value for %s, skip.", printStaticTarget(static))
				continue
			}
		}

		if static.Method != "" {
			processed := false
			/*still way too hackish, but : inject all the results in enriched, and */
			if enricherPlugin, ok := n.EnrichFunctions.Registered[static.Method]; ok {
				clog.Tracef("Found method '%s'", static.Method)
				ret, err := enricherPlugin.EnrichFunc(value, event, enricherPlugin.Ctx, n.Logger)
				if err != nil {
					clog.Errorf("method '%s' returned an error : %v", static.Method, err)
				}
				processed = true
				clog.Debugf("+ Method %s('%s') returned %d entries to merge in .Enriched\n", static.Method, value, len(ret))
				//Hackish check, but those methods do not return any data by design
				if len(ret) == 0 && static.Method != "UnmarshalJSON" {
					clog.Debugf("+ Method '%s' empty response on '%s'", static.Method, value)
				}
				for k, v := range ret {
					clog.Debugf("\t.Enriched[%s] = '%s'\n", k, v)
					event.Enriched[k] = v
				}
			} else {
				clog.Debugf("method '%s' doesn't exist or plugin not initialized", static.Method)
			}
			if !processed {
				clog.Debugf("method '%s' doesn't exist", static.Method)
			}
		} else if static.Parsed != "" {
			clog.Debugf(".Parsed[%s] = '%s'", static.Parsed, value)
			event.Parsed[static.Parsed] = value
		} else if static.Meta != "" {
			clog.Debugf(".Meta[%s] = '%s'", static.Meta, value)
			event.Meta[static.Meta] = value
		} else if static.Enriched != "" {
			clog.Debugf(".Enriched[%s] = '%s'", static.Enriched, value)
			event.Enriched[static.Enriched] = value
		} else if static.TargetByName != "" {
			if !SetTargetByName(static.TargetByName, value, event) {
				clog.Errorf("Unable to set value of '%s'", static.TargetByName)
			} else {
				clog.Debugf("%s = '%s'", static.TargetByName, value)
			}
		} else {
			clog.Fatal("unable to process static : unknown target")
		}

	}
	return nil
}

var NodesHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_node_hits_total",
		Help: "Total events entered node.",
	},
	[]string{"source", "type", "name"},
)

var NodesHitsOk = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_node_hits_ok_total",
		Help: "Total events successfully exited node.",
	},
	[]string{"source", "type", "name"},
)

var NodesHitsKo = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_node_hits_ko_total",
		Help: "Total events unsuccessfully exited node.",
	},
	[]string{"source", "type", "name"},
)

func stageidx(stage string, stages []string) int {
	for i, v := range stages {
		if stage == v {
			return i
		}
	}
	return -1
}

type ParserResult struct {
	Evt     types.Event
	Success bool
}

var ParseDump bool
var DumpFolder string
var StageParseCache map[string]map[string][]ParserResult
var StageParseMutex sync.Mutex

func Parse(ctx UnixParserCtx, xp types.Event, nodes []Node) (types.Event, error) {
	var event = xp

	/* the stage is undefined, probably line is freshly acquired, set to first stage !*/
	if event.Stage == "" && len(ctx.Stages) > 0 {
		event.Stage = ctx.Stages[0]
		log.Tracef("no stage, set to : %s", event.Stage)
	}
	event.Process = false
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}

	if event.Parsed == nil {
		event.Parsed = make(map[string]string)
	}
	if event.Enriched == nil {
		event.Enriched = make(map[string]string)
	}
	if event.Meta == nil {
		event.Meta = make(map[string]string)
	}
	if event.Unmarshaled == nil {
		event.Unmarshaled = make(map[string]interface{})
	}
	if event.Type == types.LOG {
		log.Tracef("INPUT '%s'", event.Line.Raw)
	}

	if ParseDump {
		if StageParseCache == nil {
			StageParseMutex.Lock()
			StageParseCache = make(map[string]map[string][]ParserResult)
			StageParseCache["success"] = make(map[string][]ParserResult)
			StageParseCache["success"][""] = make([]ParserResult, 0)
			StageParseMutex.Unlock()
		}
	}

	for _, stage := range ctx.Stages {
		if ParseDump {
			StageParseMutex.Lock()
			if _, ok := StageParseCache[stage]; !ok {
				StageParseCache[stage] = make(map[string][]ParserResult)
			}
			StageParseMutex.Unlock()
		}
		/* if the node is forward in stages, seek to this stage */
		/* this is for example used by testing system to inject logs in post-syslog-parsing phase*/
		if stageidx(event.Stage, ctx.Stages) > stageidx(stage, ctx.Stages) {
			log.Tracef("skipping stage, we are already at [%s] expecting [%s]", event.Stage, stage)
			continue
		}
		log.Tracef("node stage : %s, current stage : %s", event.Stage, stage)

		/* if the stage is wrong, it means that the log didn't manage "pass" a stage with a onsuccess: next_stage tag */
		if event.Stage != stage {
			log.Debugf("Event not parsed, expected stage '%s' got '%s', abort", stage, event.Stage)
			event.Process = false
			return event, nil
		}

		isStageOK := false
		for idx, node := range nodes {
			//Only process current stage's nodes
			if event.Stage != node.Stage {
				continue
			}
			clog := log.WithFields(log.Fields{
				"node-name": node.rn,
				"stage":     event.Stage,
			})
			clog.Tracef("Processing node %d/%d -> %s", idx, len(nodes), node.rn)
			if ctx.Profiling {
				node.Profiling = true
			}
			ret, err := node.process(&event, ctx, map[string]interface{}{"evt": &event})
			if err != nil {
				clog.Errorf("Error while processing node : %v", err)
				return event, err
			}
			clog.Tracef("node (%s) ret : %v", node.rn, ret)
			if ParseDump {
				StageParseMutex.Lock()
				if len(StageParseCache[stage][node.Name]) == 0 {
					StageParseCache[stage][node.Name] = make([]ParserResult, 0)
				}
				StageParseMutex.Unlock()
				evtcopy := deepcopy.Copy(event)
				parserInfo := ParserResult{Evt: evtcopy.(types.Event), Success: ret}
				StageParseMutex.Lock()
				StageParseCache[stage][node.Name] = append(StageParseCache[stage][node.Name], parserInfo)
				StageParseMutex.Unlock()
			}
			if ret {
				isStageOK = true
			}
			if ret && node.OnSuccess == "next_stage" {
				clog.Debugf("node successful, stop end stage %s", stage)
				break
			}
			//the parsed object moved onto the next phase
			if event.Stage != stage {
				clog.Tracef("node moved stage, break and redo")
				break
			}
		}
		if !isStageOK {
			log.Debugf("Log didn't finish stage %s", event.Stage)
			event.Process = false
			return event, nil
		}

	}

	event.Process = true
	return event, nil

}
