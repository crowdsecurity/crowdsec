package parser

import (
	"github.com/mohae/deepcopy"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/crowdsec/pkg/dumps"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type StageParseCollector struct {
	mu sync.Mutex
	m  dumps.ParserResults
}

func NewStageParseCollector() *StageParseCollector {
	m := make(dumps.ParserResults)
	// preserve prior ensureStageCache behavior (optional)
	m["success"] = map[string][]dumps.ParserResult{
		"": {},
	}
	return &StageParseCollector{m: m}
}


// Add records a single node result for a stage.
func (c *StageParseCollector) Add(stage, nodeName string, evt pipeline.Event, success bool) {
	if c == nil {
		return
	}

	// copy outside the critical section
	evtcopy := deepcopy.Copy(evt).(pipeline.Event)

	c.mu.Lock()
	defer c.mu.Unlock()

	stageMap, ok := c.m[stage]
	if !ok {
		stageMap = make(map[string][]dumps.ParserResult)
		c.m[stage] = stageMap
	}

	var parserIdxInStage int
	if _, ok := stageMap[nodeName]; !ok {
		stageMap[nodeName] = make([]dumps.ParserResult, 0)
		parserIdxInStage = len(stageMap)
	} else {
		parserIdxInStage = stageMap[nodeName][0].Idx
	}

	stageMap[nodeName] = append(stageMap[nodeName], dumps.ParserResult{
		Evt:     evtcopy,
		Success: success,
		Idx:     parserIdxInStage,
	})
}



// Snapshot matches what you did for PourCollector: shallow copy map, deep copy slices.
func (c *StageParseCollector) Snapshot() dumps.ParserResults {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	out := make(dumps.ParserResults, len(c.m))
	for stage, stageMap := range c.m {
		stageOut := make(map[string][]dumps.ParserResult, len(stageMap))
		for nodeName, results := range stageMap {
			tmp := make([]dumps.ParserResult, len(results))
			copy(tmp, results)
			stageOut[nodeName] = tmp
		}
		out[stage] = stageOut
	}
	return out
}

func (c *StageParseCollector) DumpYAML() ([]byte, error) {
	if c == nil {
		return nil, nil
	}

	return yaml.Marshal(c.Snapshot())
}
