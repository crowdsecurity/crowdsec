package parser

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"

	"github.com/crowdsecurity/grokky"

	"github.com/crowdsecurity/crowdsec/pkg/enrichment"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/logging"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/namegenerator"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Node struct {
	FormatVersion string `yaml:"format"`
	// Enable config + runtime debug of node via config o/
	Debug bool `yaml:"debug,omitempty"`
	// If enabled, the node (and its child) will report their own statistics
	Profiling bool `yaml:"profiling,omitempty"`
	// Name, author, description and reference(s) for parser pattern
	Name        string   `yaml:"name,omitempty"`
	Author      string   `yaml:"author,omitempty"`
	Description string   `yaml:"description,omitempty"`
	References  []string `yaml:"references,omitempty"`
	// if debug is present in the node, keep its specific Logger in runtime structure
	Logger *log.Entry `yaml:"-"`
	// This is mostly a hack to make writing less repetitive.
	// relying on stage, we know which field to parse, and we
	// can also promote log to next stage on success
	Stage string `yaml:"stage,omitempty"`
	// OnSuccess allows to tag a node to be able to move log to next stage on success
	OnSuccess string `yaml:"onsuccess,omitempty"`
	rn        string // this is only for us in debug, a random generated name for each node
	// Filter is executed at runtime (with current log line as context)
	// and must succeed or node is exited
	Filter        string      `yaml:"filter,omitempty"`
	RunTimeFilter *vm.Program `yaml:"-"` // the actual compiled filter
	// If node has leafs, execute all of them until one asks for a 'break'
	LeavesNodes []Node `yaml:"nodes,omitempty"`
	// Flag used to describe when to 'break' or return an 'error'
	EnrichFunctions EnricherCtx

	/* If the node is actually a leaf, it can have : grok, enrich, statics */
	// pattern_syntax are named grok patterns that are re-utilized over several grok patterns
	SubGroks yaml.MapSlice `yaml:"pattern_syntax,omitempty"`

	// Holds a grok pattern
	Grok        GrokPattern        `yaml:"grok,omitempty"`
	RuntimeGrok RuntimeGrokPattern `yaml:"-"`
	// Statics can be present in any type of node and is executed last
	Statics        []Static        `yaml:"statics,omitempty"`
	RuntimeStatics []RuntimeStatic `yaml:"-"`
	// Stash allows to capture data from the log line and store it in an accessible cache
	Stashes []Stash `yaml:"stash,omitempty"`
	RuntimeStashes []RuntimeStash `yaml:"-"`
	// Whitelists
	Whitelist Whitelist                  `yaml:"whitelist,omitempty"`
	Data      []*enrichment.DataProvider `yaml:"data,omitempty"`
}

func (n *Node) validate(ectx EnricherCtx) error {
	// stage is being set automagically
	if n.Stage == "" {
		return errors.New("stage needs to be an existing stage")
	}

	/* "" behaves like continue */
	if n.OnSuccess != "continue" && n.OnSuccess != "next_stage" && n.OnSuccess != "" {
		return fmt.Errorf("onsuccess %q not continue,next_stage", n.OnSuccess)
	}

	if n.Filter != "" && n.RunTimeFilter == nil {
		return fmt.Errorf("non-empty filter %q was not compiled", n.Filter)
	}

	if n.RuntimeGrok.RunTimeRegexp != nil || n.Grok.TargetField != "" {
		if err := n.Grok.Validate(); err != nil {
			return err
		}
	}

	for idx, static := range n.Statics {
		if err := static.Validate(ectx); err != nil {
			return fmt.Errorf("static %d: %w", idx, err)
		}
	}

	for idx, stash := range n.Stashes {
		if err := stash.Validate(); err != nil {
			return fmt.Errorf("stash %d: %w", idx, err)
		}
	}

	return nil
}

func (n *Node) processFilter(cachedExprEnv map[string]any) (bool, error) {
	clog := n.Logger
	if n.RunTimeFilter == nil {
		clog.Trace("Node has no filter, enter")
		return true, nil
	}

	// Evaluate node's filter
	output, err := exprhelpers.Run(n.RunTimeFilter, cachedExprEnv, clog, n.Debug)
	if err != nil {
		clog.Warningf("failed to run filter: %v", err)
		clog.Debug("Event leaving node: ko")

		return false, nil
	}

	switch out := output.(type) {
	case bool:
		if !out {
			clog.Debug("Event leaving node: ko (failed filter)")
			return false, nil
		}
	default:
		clog.Warningf("Expr %q returned non-bool, abort: %T", n.Filter, output)
		clog.Debug("Event leaving node: ko")

		return false, nil
	}

	return true, nil
}

func (n *Node) processWhitelist(cachedExprEnv map[string]any, p *pipeline.Event) (bool, error) {
	var exprErr error

	isWhitelisted := n.CheckIPsWL(p)
	if !isWhitelisted {
		isWhitelisted, exprErr = n.CheckExprWL(cachedExprEnv, p)
	}

	if exprErr != nil {
		// Previous code returned nil if there was an error, so we keep this behavior
		return false, nil //nolint:nilerr
	}

	if isWhitelisted && !p.Whitelisted {
		p.Whitelisted = true
		p.WhitelistReason = n.Whitelist.Reason
		// huglily wipe the ban order if the event is whitelisted and it's an overflow
		if p.Type == pipeline.OVFLW { // don't do this at home kids
			ips := []string{}
			for k := range p.Overflow.Sources {
				ips = append(ips, k)
			}

			n.Logger.Infof("Ban for %s whitelisted, reason [%s]", strings.Join(ips, ","), n.Whitelist.Reason)

			p.Overflow.Whitelisted = true
		}
	}

	return isWhitelisted, nil
}

func (n *Node) processGrok(p *pipeline.Event, cachedExprEnv map[string]any) (bool, bool, error) {
	// Process grok if present, should be exclusive with nodes :)
	var nodeHasOKGrok bool

	clog := n.Logger
	gstr := ""

	if n.RuntimeGrok.RunTimeRegexp == nil {
		clog.Tracef("! No grok pattern: %p", n.RuntimeGrok.RunTimeRegexp)
		return true, false, nil
	}

	clog.Tracef("Processing grok pattern: %s: %p", n.Grok.RegexpName, n.RuntimeGrok.RunTimeRegexp)
	// for unparsed, parsed etc. set sensible defaults to reduce user hassle
	if n.Grok.TargetField != "" {
		// it's a hack to avoid using real reflect
		if n.Grok.TargetField == "Line.Raw" {
			gstr = p.Line.Raw
		} else if val, ok := p.Parsed[n.Grok.TargetField]; ok {
			gstr = val
		} else {
			clog.Debugf("(%s) target field %q doesn't exist in %v", n.rn, n.Grok.TargetField, p.Parsed)
			return false, false, nil
		}
	} else if n.RuntimeGrok.RunTimeValue != nil {
		output, err := exprhelpers.Run(n.RuntimeGrok.RunTimeValue, cachedExprEnv, clog, n.Debug)
		if err != nil {
			clog.Warningf("failed to run RunTimeValue: %v", err)
			return false, false, nil
		}

		switch out := output.(type) {
		case string:
			gstr = out
		case int:
			gstr = strconv.Itoa(out)
		case float64, float32:
			gstr = fmt.Sprintf("%f", out)
		default:
			clog.Errorf("unexpected return type for RunTimeValue: %T", output)
		}
	}

	var groklabel string
	if n.Grok.RegexpName == "" {
		groklabel = fmt.Sprintf("%5.5s...", n.Grok.RegexpValue)
	} else {
		groklabel = n.Grok.RegexpName
	}

	grok := n.RuntimeGrok.RunTimeRegexp.Parse(gstr)

	if len(grok) == 0 {
		// grok failed, node failed
		clog.Debugf("+ Grok %q didn't return data on %q", groklabel, gstr)
		return false, false, nil
	}

	// tag explicitly that the *current* node had a successful grok pattern. it's important to know success state
	nodeHasOKGrok = true

	clog.Debugf("+ Grok %q returned %d entries to merge in Parsed", groklabel, len(grok))
	// We managed to grok stuff, merged into parse
	for k, v := range grok {
		clog.Debugf("\t.Parsed[%q] = %q", k, v)
		p.Parsed[k] = v
	}
	// if the grok succeed, process associated statics
	err := n.RuntimeGrok.ProcessStatics(p, n.EnrichFunctions, clog, n.Debug)
	if err != nil {
		clog.Errorf("(%s) Failed to process statics: %v", n.rn, err)
		return false, false, err
	}

	return true, nodeHasOKGrok, nil
}

func (n *Node) processStash(_ *pipeline.Event, cachedExprEnv map[string]any) error {
	for idx, stash := range n.RuntimeStashes {
		stash.Apply(idx, cachedExprEnv, n.Logger, n.Debug)
	}

	return nil
}

func (n *Node) processLeaves(
	p *pipeline.Event,
	ctx UnixParserCtx,
	cachedExprEnv map[string]any,
	initialState bool,
	nodeHasOKGrok bool,
) (bool, error) {
	nodeState := initialState

	for idx := range n.LeavesNodes {
		child := &n.LeavesNodes[idx]

		ret, err := child.process(p, ctx, cachedExprEnv)
		if err != nil {
			n.Logger.Tracef("\tNode (%s) failed: %v", child.rn, err)
			n.Logger.Debugf("Event leaving node: ko")

			return false, err
		}

		n.Logger.Tracef("\tsub-node (%s) ret: %v (strategy:%s)", child.rn, ret, n.OnSuccess)

		if ret {
			nodeState = true
			/* if child is successful, stop processing */
			if n.OnSuccess == "next_stage" {
				n.Logger.Debugf("child is success, OnSuccess=next_stage, skip")
				break
			}
		} else if !nodeHasOKGrok {
			/*
				If the parent node has a successful grok pattern, its state will stay successful even if one or more childs fail.
				If the parent node is a skeleton node (no grok pattern), then at least one child must be successful for it to be a success.
			*/
			nodeState = false
		}
	}

	return nodeState, nil
}

func (n *Node) process(p *pipeline.Event, ctx UnixParserCtx, expressionEnv map[string]any) (bool, error) {
	clog := n.Logger

	cachedExprEnv := expressionEnv

	clog.Trace("Event entering node")

	nodeState, err := n.processFilter(cachedExprEnv)
	if err != nil {
		return false, err
	}

	if !nodeState {
		return false, nil
	}

	if n.Name != "" {
		n.bumpNodeMetric(metrics.NodesHits, p)
	}

	isWhitelisted, err := n.processWhitelist(cachedExprEnv, p)
	if err != nil {
		return false, err
	}

	nodeState, nodeHasOKGrok, err := n.processGrok(p, cachedExprEnv)
	if err != nil {
		return false, err
	}

	// Process the stash (data collection) if: a grok was present and succeeded, or if there is no grok
	if nodeHasOKGrok || n.RuntimeGrok.RunTimeRegexp == nil {
		if err := n.processStash(p, cachedExprEnv); err != nil {
			return false, err
		}
	}

	leafState, err := n.processLeaves(p, ctx, cachedExprEnv, nodeState, nodeHasOKGrok)
	if err != nil {
		return false, err
	}

	nodeState = leafState

	// todo : check if a node made the state change ?
	// should the childs inherit the on_success behavior

	clog.Tracef("State after nodes: %v", nodeState)

	// grok or leafs failed, don't process statics
	if !nodeState {
		if n.Name != "" {
			n.bumpNodeMetric(metrics.NodesHitsKo, p)
		}

		clog.Debug("Event leaving node: ko")

		return nodeState, nil
	}

	if n.Name != "" {
		n.bumpNodeMetric(metrics.NodesHitsOk, p)
	}

	/*
		This is to apply statics when the node either was whitelisted, or is not a whitelist (it has no expr/ips wl)
		It is overconvoluted and should be simplified
	*/
	if len(n.Statics) > 0 && (isWhitelisted || !n.ContainsWLs()) {
		clog.Debugf("+ Processing %d statics", len(n.Statics))
		// if all else is good in whitelist, process node's statics
		err := n.ProcessStatics(p)
		if err != nil {
			clog.Errorf("Failed to process statics: %v", err)
			return false, err
		}
	} else {
		clog.Trace("! No node statics")
	}

	if nodeState {
		clog.Debug("Event leaving node : ok")
		log.Trace("node is successful, check strategy")

		if n.OnSuccess == "next_stage" {
			idx := stageidx(p.Stage, ctx.Stages)
			// we're at the last stage
			if idx+1 == len(ctx.Stages) {
				clog.Debugf("node reached the last stage: %s", p.Stage)
			} else {
				clog.Debugf("move Event from stage %s to %s", p.Stage, ctx.Stages[idx+1])
				p.Stage = ctx.Stages[idx+1]
			}
		} else {
			clog.Tracef("no strategy on success (%s), continue!", n.OnSuccess)
		}
	} else {
		clog.Debug("Event leaving node: ko")
	}

	clog.Trace("Node successful, continue")

	return nodeState, nil
}

var dumpr = spew.ConfigState{MaxDepth: 1, DisablePointerAddresses: true}

func (n *Node) compile(pctx *UnixParserCtx, ectx EnricherCtx) error {
	var err error

	valid := false

	n.rn = namegenerator.GetRandomName()

	n.EnrichFunctions = ectx
	log.Tracef("compile, node is %s", n.Stage)
	/* if the node has debugging enabled, create a specific logger with debug
	that will be used only for processing this node ;) */

	var clog *log.Entry

	if n.Debug {
		clog = logging.SubLogger(log.StandardLogger(), "parser", log.DebugLevel)
		clog.Infof("%s has debug enabled", n.Name)
	} else {
		/* else bind it to the default one (might find something more elegant here)*/
		clog = log.WithField("module", "parser")
	}

	n.Logger = clog.WithField("id", n.rn)

	/* display info about top-level nodes, they should be the only one with explicit stage name ?*/
	n.Logger = n.Logger.WithFields(log.Fields{"stage": n.Stage, "name": n.Name})

	if n.Logger.Logger.IsLevelEnabled(log.TraceLevel) {
		n.Logger.Tracef("Compiling: %s", dumpr.Sdump(n))
	}

	// compile filter if present
	if n.Filter != "" {
		n.RunTimeFilter, err = expr.Compile(n.Filter, exprhelpers.GetExprOptions(map[string]any{"evt": &pipeline.Event{}})...)
		if err != nil {
			return fmt.Errorf("compilation of %q failed: %v", n.Filter, err)
		}
	}

	/* handle pattern_syntax and groks */
	for _, pattern := range n.SubGroks {
		n.Logger.Tracef("Adding subpattern '%s': '%s'", pattern.Key, pattern.Value)

		if err = pctx.Grok.Add(pattern.Key.(string), pattern.Value.(string)); err != nil {
			if errors.Is(err, grokky.ErrAlreadyExist) {
				n.Logger.Warningf("grok '%s' already registred", pattern.Key)
				continue
			}

			n.Logger.Errorf("Unable to compile subpattern %s: %v", pattern.Key, err)

			return err
		}
	}

	if n.Grok.RegexpName != "" || n.Grok.RegexpValue != "" || n.Grok.ExpValue != "" {
		rg, err := n.Grok.Compile(pctx, n.Logger)
		if err != nil {
			return err
		}

		n.RuntimeGrok = *rg
		valid = true
	}

	for _, stash := range n.Stashes {
		compiled, err := stash.Compile(n.Logger)
		if err != nil {
			return fmt.Errorf("stash %s: %w", stash.Name, err)
		}
		n.RuntimeStashes = append(n.RuntimeStashes, *compiled)
	}

	/* compile leafs if present */
	for idx := range n.LeavesNodes {
		if n.LeavesNodes[idx].Name == "" {
			n.LeavesNodes[idx].Name = "child-" + n.Name
		}

		// propagate debug/stats to child nodes
		if !n.LeavesNodes[idx].Debug && n.Debug {
			n.LeavesNodes[idx].Debug = true
		}

		if !n.LeavesNodes[idx].Profiling && n.Profiling {
			n.LeavesNodes[idx].Profiling = true
		}

		n.LeavesNodes[idx].Stage = n.Stage

		err = n.LeavesNodes[idx].compile(pctx, ectx)
		if err != nil {
			return err
		}

		valid = true
	}

	/* load statics if present */
	for _, static := range n.Statics {
		compiled, err := static.Compile()
		if err != nil {
			return err
		}

		n.RuntimeStatics = append(n.RuntimeStatics, *compiled)

		valid = true
	}

	/* compile whitelists if present */
	whitelistValid, err := n.CompileWLs()
	if err != nil {
		return err
	}

	valid = valid || whitelistValid

	if !valid {
		/* node is empty, error force return */
		n.Logger.Error("Node is empty or invalid, abort")
		n.Stage = ""

		return errors.New("Node is empty")
	}

	return n.validate(ectx)
}

func (n *Node) bumpNodeMetric(counter *prometheus.CounterVec, p *pipeline.Event) {
	// better safe than sorry
	acquisType := p.Line.Labels["type"]
	if acquisType == "" {
		acquisType = "unknown"
	}

	labels := prometheus.Labels{
		"source":      p.Line.Src,
		"type":        p.Line.Module,
		"name":        n.Name,
		"stage":       p.Stage,
		"acquis_type": acquisType,
	}
	counter.With(labels).Inc()
}
