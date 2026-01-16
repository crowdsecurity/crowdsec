package parser

/*
 This file contains
 - the runtime parsing routines
*/

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mohae/deepcopy"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/dumps"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

/* ok, this is kinda experimental, I don't know how bad of an idea it is .. */
func SetTargetByName(target string, value string, evt *pipeline.Event) bool {
	if evt == nil {
		return false
	}

	// it's a hack, we do it for the user
	target = strings.TrimPrefix(target, "evt.")

	log.Debugf("setting target %s to %s", target, value)

	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Runtime error while trying to set '%s': %+v", target, r)
			return
		}
	}()

	iter := reflect.ValueOf(evt).Elem()
	if !iter.IsValid() || iter.IsZero() {
		log.Trace("event is nil")
		return false
	}

	for f := range strings.SplitSeq(target, ".") {
		/*
		** According to current Event layout we only have to handle struct and map
		 */
		switch iter.Kind() { //nolint:exhaustive
		case reflect.Map:
			tmp := iter.MapIndex(reflect.ValueOf(f))
			// if we're in a map and the field doesn't exist, the user wants to add it :)
			if !tmp.IsValid() || tmp.IsZero() {
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
		case reflect.Ptr:
			tmp := iter.Elem()
			iter = reflect.Indirect(tmp.FieldByName(f))
		default:
			log.Errorf("unexpected type %s in '%s'", iter.Kind(), target)
			return false
		}
	}

	// now we should have the final member :)
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

// targetExpr returns a human-readable selector string that describes
// where this Static will write its value in the event.
func (s *Static) targetExpr() string {
	switch {
	case s.Method != "":
		return s.Method
	case s.Parsed != "":
		return fmt.Sprintf(".Parsed[%s]", s.Parsed)
	case s.Meta != "":
		return fmt.Sprintf(".Meta[%s]", s.Meta)
	case s.Enriched != "":
		return fmt.Sprintf(".Enriched[%s]", s.Enriched)
	case s.TargetByName != "":
		return s.TargetByName
	default:
		return "?"
	}
}

func (rs *RuntimeStatic) Apply(event *pipeline.Event, enrichFunctions EnricherCtx, logger *log.Entry, debug bool) error {
	// we have a few cases :
	// (meta||key) + (static||reference||expr)
	exprEnv := map[string]any{"evt": event}
	value := ""

	if rs.Config.Value != "" {
		value = rs.Config.Value
	} else if rs.RunTimeValue != nil {
		output, err := exprhelpers.Run(rs.RunTimeValue, exprEnv, logger, debug)
		if err != nil {
			logger.Warningf("failed to run RunTimeValue : %v", err)
			return nil
		}

		switch out := output.(type) {
		case string:
			value = out
		case int:
			value = strconv.Itoa(out)
		case float64, float32:
			value = fmt.Sprintf("%f", out)
		case map[string]any:
			logger.Warnf("Expression %q returned a map, please use ToJsonString() to convert it to string if you want to keep it as is, or refine your expression to extract a string", rs.Config.ExpValue)
		case []any:
			logger.Warnf("Expression %q returned an array, please use ToJsonString() to convert it to string if you want to keep it as is, or refine your expression to extract a string", rs.Config.ExpValue)
		case nil:
			logger.Debugf("Expression %q returned nil, skipping", rs.Config.ExpValue)
		default:
			logger.Errorf("unexpected return type for %q: %T", rs.Config.ExpValue, output)
			return errors.New("unexpected return type for RunTimeValue")
		}
	}

	if value == "" {
		// allow ParseDate to have empty input
		if rs.Config.Method != "ParseDate" {
			logger.Debugf("Empty value for %s, skip.", rs.Config.targetExpr())
			return nil
		}
	}

	switch {
	case rs.Config.Method != "":
		processed := false
		/*still way too hackish, but : inject all the results in enriched, and */
		if enricherPlugin, ok := enrichFunctions.Registered[rs.Config.Method]; ok {
			logger.Tracef("Found method '%s'", rs.Config.Method)

			ret, err := enricherPlugin.EnrichFunc(value, event, logger.WithField("method", rs.Config.Method))
			if err != nil {
				logger.Errorf("method '%s' returned an error : %v", rs.Config.Method, err)
			}

			processed = true

			logger.Debugf("+ Method %s('%s') returned %d entries to merge in .Enriched\n", rs.Config.Method, value, len(ret))
			// Hackish check, but those methods do not return any data by design
			if len(ret) == 0 && rs.Config.Method != "UnmarshalJSON" {
				logger.Debugf("+ Method '%s' empty response on '%s'", rs.Config.Method, value)
			}

			for k, v := range ret {
				logger.Debugf("\t.Enriched[%s] = '%s'\n", k, v)
				event.Enriched[k] = v
			}
		} else {
			logger.Debugf("method '%s' doesn't exist or plugin not initialized", rs.Config.Method)
		}

		if !processed {
			logger.Debugf("method '%s' doesn't exist", rs.Config.Method)
		}
	case rs.Config.Parsed != "":
		logger.Debugf(".Parsed[%s] = '%s'", rs.Config.Parsed, value)
		event.Parsed[rs.Config.Parsed] = value
	case rs.Config.Meta != "":
		logger.Debugf(".Meta[%s] = '%s'", rs.Config.Meta, value)
		event.Meta[rs.Config.Meta] = value
	case rs.Config.Enriched != "":
		logger.Debugf(".Enriched[%s] = '%s'", rs.Config.Enriched, value)
		event.Enriched[rs.Config.Enriched] = value
	case rs.Config.TargetByName != "":
		if !SetTargetByName(rs.Config.TargetByName, value, event) {
			logger.Errorf("Unable to set value of '%s'", rs.Config.TargetByName)
		} else {
			logger.Debugf("%s = '%s'", rs.Config.TargetByName, value)
		}
	default:
		logger.Fatal("unable to process static : unknown target")
	}

	return nil
}

func (n *Node) ProcessStatics(event *pipeline.Event) error {
	for _, rs := range n.RuntimeStatics {
		if err := rs.Apply(event, n.EnrichFunctions, n.Logger, n.Debug); err != nil {
			return fmt.Errorf("applying %s: %w", rs.Config.targetExpr(), err)
		}
	}

	return nil
}

func (rg *RuntimeGrokPattern) ProcessStatics(event *pipeline.Event, ectx EnricherCtx, logger *log.Entry, debug bool) error {
	for _, rs := range rg.RuntimeStatics {
		if err := rs.Apply(event, ectx, logger, debug); err != nil {
			return fmt.Errorf("applying %s: %w", rs.Config.targetExpr(), err)
		}
	}

	return nil
}

func stageidx(stage string, stages []string) int {
	for i, v := range stages {
		if stage == v {
			return i
		}
	}

	return -1
}

var (
	StageParseCache dumps.ParserResults = make(dumps.ParserResults)
	StageParseMutex sync.Mutex
	// initialize the cache only once, even if called concurrently
	ensureStageCache = sync.OnceFunc(func() {
		StageParseCache["success"] = make(map[string][]dumps.ParserResult)
		StageParseCache["success"][""] = make([]dumps.ParserResult, 0)
	})
)

func Parse(ctx UnixParserCtx, xp pipeline.Event, nodes []Node, dump bool) (pipeline.Event, error) {
	event := xp

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
		event.Unmarshaled = make(map[string]any)
	}

	if event.Type == pipeline.LOG {
		log.Tracef("INPUT '%s'", event.Line.Raw)
	}

	if dump {
		ensureStageCache()
	}

	exprEnv := map[string]any{"evt": &event}

	for _, stage := range ctx.Stages {
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

		for idx := range nodes {
			// Only process current stage's nodes
			if event.Stage != nodes[idx].Stage {
				continue
			}

			clog := log.WithFields(log.Fields{
				"node-name": nodes[idx].rn,
				"stage":     event.Stage,
			})

			clog.Tracef("Processing node %d/%d -> %s", idx, len(nodes), nodes[idx].rn)

			if ctx.Profiling {
				nodes[idx].Profiling = true
			}

			ret, err := nodes[idx].process(&event, ctx, exprEnv)
			if err != nil {
				clog.Errorf("Error while processing node : %v", err)
				return event, err
			}

			clog.Tracef("node (%s) ret : %v", nodes[idx].rn, ret)

			if dump {
				var parserIdxInStage int

				// copy outside of critical section
				evtcopy := deepcopy.Copy(event)
				name := nodes[idx].Name

				// ensure the stage map exists
				StageParseMutex.Lock()

				stageMap, ok := StageParseCache[stage]
				if !ok {
					stageMap = make(map[string][]dumps.ParserResult)
					StageParseCache[stage] = stageMap
				}

				// ensure the slice for this parser exists
				if _, ok := stageMap[name]; !ok {
					stageMap[name] = make([]dumps.ParserResult, 0)
					parserIdxInStage = len(stageMap)
				} else {
					parserIdxInStage = stageMap[name][0].Idx
				}

				stageMap[name] = append(stageMap[name], dumps.ParserResult{
					Evt:     evtcopy.(pipeline.Event),
					Success: ret, Idx: parserIdxInStage,
				})

				StageParseMutex.Unlock()
			}

			if ret {
				isStageOK = true
			}

			if ret && nodes[idx].OnSuccess == "next_stage" {
				clog.Debugf("node successful, stop end stage %s", stage)
				break
			}

			// the parsed object moved onto the next phase
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
