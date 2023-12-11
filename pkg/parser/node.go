package parser

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/davecgh/go-spew/spew"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"

	"github.com/crowdsecurity/grokky"

	"github.com/crowdsecurity/crowdsec/pkg/cache"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type Node struct {
	FormatVersion string `yaml:"format"`
	//Enable config + runtime debug of node via config o/
	Debug bool `yaml:"debug,omitempty"`
	//If enabled, the node (and its child) will report their own statistics
	Profiling bool `yaml:"profiling,omitempty"`
	//Name, author, description and reference(s) for parser pattern
	Name        string   `yaml:"name,omitempty"`
	Author      string   `yaml:"author,omitempty"`
	Description string   `yaml:"description,omitempty"`
	References  []string `yaml:"references,omitempty"`
	//if debug is present in the node, keep its specific Logger in runtime structure
	Logger *log.Entry `yaml:"-"`
	//This is mostly a hack to make writing less repetitive.
	//relying on stage, we know which field to parse, and we
	//can also promote log to next stage on success
	Stage string `yaml:"stage,omitempty"`
	//OnSuccess allows to tag a node to be able to move log to next stage on success
	OnSuccess string `yaml:"onsuccess,omitempty"`
	rn        string //this is only for us in debug, a random generated name for each node
	//Filter is executed at runtime (with current log line as context)
	//and must succeed or node is exited
	Filter        string      `yaml:"filter,omitempty"`
	RunTimeFilter *vm.Program `yaml:"-" json:"-"` //the actual compiled filter
	//If node has leafs, execute all of them until one asks for a 'break'
	LeavesNodes []Node `yaml:"nodes,omitempty"`
	//Flag used to describe when to 'break' or return an 'error'
	EnrichFunctions EnricherCtx

	/* If the node is actually a leaf, it can have : grok, enrich, statics */
	//pattern_syntax are named grok patterns that are re-utilized over several grok patterns
	SubGroks yaml.MapSlice `yaml:"pattern_syntax,omitempty"`

	//Holds a grok pattern
	Grok GrokPattern `yaml:"grok,omitempty"`
	//Statics can be present in any type of node and is executed last
	Statics []ExtraField `yaml:"statics,omitempty"`
	//Stash allows to capture data from the log line and store it in an accessible cache
	Stash []DataCapture `yaml:"stash,omitempty"`
	//Whitelists
	Whitelist Whitelist           `yaml:"whitelist,omitempty"`
	Data      []*types.DataSource `yaml:"data,omitempty"`
}

func (n *Node) validate(pctx *UnixParserCtx, ectx EnricherCtx) error {

	//stage is being set automagically
	if n.Stage == "" {
		return fmt.Errorf("stage needs to be an existing stage")
	}

	/* "" behaves like continue */
	if n.OnSuccess != "continue" && n.OnSuccess != "next_stage" && n.OnSuccess != "" {
		return fmt.Errorf("onsuccess '%s' not continue,next_stage", n.OnSuccess)
	}
	if n.Filter != "" && n.RunTimeFilter == nil {
		return fmt.Errorf("non-empty filter '%s' was not compiled", n.Filter)
	}

	if n.Grok.RunTimeRegexp != nil || n.Grok.TargetField != "" {
		if n.Grok.TargetField == "" && n.Grok.ExpValue == "" {
			return fmt.Errorf("grok requires 'expression' or 'apply_on'")
		}
		if n.Grok.RegexpName == "" && n.Grok.RegexpValue == "" {
			return fmt.Errorf("grok needs 'pattern' or 'name'")
		}
	}

	for idx, static := range n.Statics {
		if static.Method != "" {
			if static.ExpValue == "" {
				return fmt.Errorf("static %d : when method is set, expression must be present", idx)
			}
			if _, ok := ectx.Registered[static.Method]; !ok {
				log.Warningf("the method '%s' doesn't exist or the plugin has not been initialized", static.Method)
			}
		} else {
			if static.Meta == "" && static.Parsed == "" && static.TargetByName == "" {
				return fmt.Errorf("static %d : at least one of meta/event/target must be set", idx)
			}
			if static.Value == "" && static.RunTimeValue == nil {
				return fmt.Errorf("static %d value or expression must be set", idx)
			}
		}
	}

	for idx, stash := range n.Stash {
		if stash.Name == "" {
			return fmt.Errorf("stash %d : name must be set", idx)
		}
		if stash.Value == "" {
			return fmt.Errorf("stash %s : value expression must be set", stash.Name)
		}
		if stash.Key == "" {
			return fmt.Errorf("stash %s : key expression must be set", stash.Name)
		}
		if stash.TTL == "" {
			return fmt.Errorf("stash %s : ttl must be set", stash.Name)
		}
		if stash.Strategy == "" {
			stash.Strategy = "LRU"
		}
		//should be configurable
		if stash.MaxMapSize == 0 {
			stash.MaxMapSize = 100
		}
	}
	return nil
}

func (n *Node) process(p *types.Event, ctx UnixParserCtx, expressionEnv map[string]interface{}) (bool, error) {
	var NodeState bool
	var NodeHasOKGrok bool
	clog := n.Logger

	cachedExprEnv := expressionEnv

	clog.Tracef("Event entering node")
	if n.RunTimeFilter != nil {
		//Evaluate node's filter
		output, err := exprhelpers.Run(n.RunTimeFilter, cachedExprEnv, clog, n.Debug)
		if err != nil {
			clog.Warningf("failed to run filter : %v", err)
			clog.Debugf("Event leaving node : ko")
			return false, nil
		}

		switch out := output.(type) {
		case bool:
			if !out {
				clog.Debugf("Event leaving node : ko (failed filter)")
				return false, nil
			}
		default:
			clog.Warningf("Expr '%s' returned non-bool, abort : %T", n.Filter, output)
			clog.Debugf("Event leaving node : ko")
			return false, nil
		}
		NodeState = true
	} else {
		clog.Tracef("Node has not filter, enter")
		NodeState = true
	}

	if n.Name != "" {
		NodesHits.With(prometheus.Labels{"source": p.Line.Src, "type": p.Line.Module, "name": n.Name}).Inc()
	}
	exprErr := error(nil)
	isWhitelisted := n.CheckIPsWL(p.ParseIPSources())
	if !isWhitelisted {
		isWhitelisted, exprErr = n.CheckExprWL(cachedExprEnv)
	}
	if exprErr != nil {
		// Previous code returned nil if there was an error, so we keep this behavior
		return false, nil //nolint:nilerr
	}
	if isWhitelisted && !p.Whitelisted {
		p.Whitelisted = true
		p.WhitelistReason = n.Whitelist.Reason
		/*huglily wipe the ban order if the event is whitelisted and it's an overflow */
		if p.Type == types.OVFLW { /*don't do this at home kids */
			ips := []string{}
			for k := range p.Overflow.Sources {
				ips = append(ips, k)
			}
			clog.Infof("Ban for %s whitelisted, reason [%s]", strings.Join(ips, ","), n.Whitelist.Reason)
			p.Overflow.Whitelisted = true
		}
	}

	//Process grok if present, should be exclusive with nodes :)
	gstr := ""
	if n.Grok.RunTimeRegexp != nil {
		clog.Tracef("Processing grok pattern : %s : %p", n.Grok.RegexpName, n.Grok.RunTimeRegexp)
		//for unparsed, parsed etc. set sensible defaults to reduce user hassle
		if n.Grok.TargetField != "" {
			//it's a hack to avoid using real reflect
			if n.Grok.TargetField == "Line.Raw" {
				gstr = p.Line.Raw
			} else if val, ok := p.Parsed[n.Grok.TargetField]; ok {
				gstr = val
			} else {
				clog.Debugf("(%s) target field '%s' doesn't exist in %v", n.rn, n.Grok.TargetField, p.Parsed)
				NodeState = false
			}
		} else if n.Grok.RunTimeValue != nil {
			output, err := exprhelpers.Run(n.Grok.RunTimeValue, cachedExprEnv, clog, n.Debug)
			if err != nil {
				clog.Warningf("failed to run RunTimeValue : %v", err)
				NodeState = false
			}
			switch out := output.(type) {
			case string:
				gstr = out
			case int:
				gstr = fmt.Sprintf("%d", out)
			case float64, float32:
				gstr = fmt.Sprintf("%f", out)
			default:
				clog.Errorf("unexpected return type for RunTimeValue : %T", output)
			}
		}

		var groklabel string
		if n.Grok.RegexpName == "" {
			groklabel = fmt.Sprintf("%5.5s...", n.Grok.RegexpValue)
		} else {
			groklabel = n.Grok.RegexpName
		}
		grok := n.Grok.RunTimeRegexp.Parse(gstr)
		if len(grok) > 0 {
			/*tag explicitly that the *current* node had a successful grok pattern. it's important to know success state*/
			NodeHasOKGrok = true
			clog.Debugf("+ Grok '%s' returned %d entries to merge in Parsed", groklabel, len(grok))
			//We managed to grok stuff, merged into parse
			for k, v := range grok {
				clog.Debugf("\t.Parsed['%s'] = '%s'", k, v)
				p.Parsed[k] = v
			}
			// if the grok succeed, process associated statics
			err := n.ProcessStatics(n.Grok.Statics, p)
			if err != nil {
				clog.Errorf("(%s) Failed to process statics : %v", n.rn, err)
				return false, err
			}
		} else {
			//grok failed, node failed
			clog.Debugf("+ Grok '%s' didn't return data on '%s'", groklabel, gstr)
			NodeState = false
		}

	} else {
		clog.Tracef("! No grok pattern : %p", n.Grok.RunTimeRegexp)
	}

	//Process the stash (data collection) if : a grok was present and succeeded, or if there is no grok
	if NodeHasOKGrok || n.Grok.RunTimeRegexp == nil {
		for idx, stash := range n.Stash {
			var value string
			var key string
			if stash.ValueExpression == nil {
				clog.Warningf("Stash %d has no value expression, skipping", idx)
				continue
			}
			if stash.KeyExpression == nil {
				clog.Warningf("Stash %d has no key expression, skipping", idx)
				continue
			}
			//collect the data
			output, err := exprhelpers.Run(stash.ValueExpression, cachedExprEnv, clog, n.Debug)
			if err != nil {
				clog.Warningf("Error while running stash val expression : %v", err)
			}
			//can we expect anything else than a string ?
			switch output := output.(type) {
			case string:
				value = output
			default:
				clog.Warningf("unexpected type %t (%v) while running '%s'", output, output, stash.Value)
				continue
			}

			//collect the key
			output, err = exprhelpers.Run(stash.KeyExpression, cachedExprEnv, clog, n.Debug)
			if err != nil {
				clog.Warningf("Error while running stash key expression : %v", err)
			}
			//can we expect anything else than a string ?
			switch output := output.(type) {
			case string:
				key = output
			default:
				clog.Warningf("unexpected type %t (%v) while running '%s'", output, output, stash.Key)
				continue
			}
			cache.SetKey(stash.Name, key, value, &stash.TTLVal)
		}
	}

	//Iterate on leafs
	for _, leaf := range n.LeavesNodes {
		ret, err := leaf.process(p, ctx, cachedExprEnv)
		if err != nil {
			clog.Tracef("\tNode (%s) failed : %v", leaf.rn, err)
			clog.Debugf("Event leaving node : ko")
			return false, err
		}
		clog.Tracef("\tsub-node (%s) ret : %v (strategy:%s)", leaf.rn, ret, n.OnSuccess)
		if ret {
			NodeState = true
			/* if child is successful, stop processing */
			if n.OnSuccess == "next_stage" {
				clog.Debugf("child is success, OnSuccess=next_stage, skip")
				break
			}
		} else if !NodeHasOKGrok {
			/*
				If the parent node has a successful grok pattern, it's state will stay successful even if one or more chil fails.
				If the parent node is a skeleton node (no grok pattern), then at least one child must be successful for it to be a success.
			*/
			NodeState = false
		}
	}
	/*todo : check if a node made the state change ?*/
	/* should the childs inherit the on_success behavior */

	clog.Tracef("State after nodes : %v", NodeState)

	//grok or leafs failed, don't process statics
	if !NodeState {
		if n.Name != "" {
			NodesHitsKo.With(prometheus.Labels{"source": p.Line.Src, "type": p.Line.Module, "name": n.Name}).Inc()
		}
		clog.Debugf("Event leaving node : ko")
		return NodeState, nil
	}

	if n.Name != "" {
		NodesHitsOk.With(prometheus.Labels{"source": p.Line.Src, "type": p.Line.Module, "name": n.Name}).Inc()
	}

	/*
		This is to apply statics when the node either was whitelisted, or is not a whitelist (it has no expr/ips wl)
		It is overconvoluted and should be simplified
	*/
	if len(n.Statics) > 0 && (isWhitelisted || !n.ContainsWLs()) {
		clog.Debugf("+ Processing %d statics", len(n.Statics))
		// if all else is good in whitelist, process node's statics
		err := n.ProcessStatics(n.Statics, p)
		if err != nil {
			clog.Errorf("Failed to process statics : %v", err)
			return false, err
		}
	} else {
		clog.Tracef("! No node statics")
	}

	if NodeState {
		clog.Debugf("Event leaving node : ok")
		log.Tracef("node is successful, check strategy")
		if n.OnSuccess == "next_stage" {
			idx := stageidx(p.Stage, ctx.Stages)
			//we're at the last stage
			if idx+1 == len(ctx.Stages) {
				clog.Debugf("node reached the last stage : %s", p.Stage)
			} else {
				clog.Debugf("move Event from stage %s to %s", p.Stage, ctx.Stages[idx+1])
				p.Stage = ctx.Stages[idx+1]
			}
		} else {
			clog.Tracef("no strategy on success (%s), continue !", n.OnSuccess)
		}
	} else {
		clog.Debugf("Event leaving node : ko")
	}
	clog.Tracef("Node successful, continue")
	return NodeState, nil
}

func (n *Node) compile(pctx *UnixParserCtx, ectx EnricherCtx) error {
	var err error
	var valid bool

	valid = false

	dumpr := spew.ConfigState{MaxDepth: 1, DisablePointerAddresses: true}
	n.rn = seed.Generate()

	n.EnrichFunctions = ectx
	log.Tracef("compile, node is %s", n.Stage)
	/* if the node has debugging enabled, create a specific logger with debug
	that will be used only for processing this node ;) */
	if n.Debug {
		var clog = log.New()
		if err = types.ConfigureLogger(clog); err != nil {
			log.Fatalf("While creating bucket-specific logger : %s", err)
		}
		clog.SetLevel(log.DebugLevel)
		n.Logger = clog.WithFields(log.Fields{
			"id": n.rn,
		})
		n.Logger.Infof("%s has debug enabled", n.Name)
	} else {
		/* else bind it to the default one (might find something more elegant here)*/
		n.Logger = log.WithFields(log.Fields{
			"id": n.rn,
		})
	}

	/* display info about top-level nodes, they should be the only one with explicit stage name ?*/
	n.Logger = n.Logger.WithFields(log.Fields{"stage": n.Stage, "name": n.Name})

	n.Logger.Tracef("Compiling : %s", dumpr.Sdump(n))

	//compile filter if present
	if n.Filter != "" {
		n.RunTimeFilter, err = expr.Compile(n.Filter, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		if err != nil {
			return fmt.Errorf("compilation of '%s' failed: %v", n.Filter, err)
		}
	}

	/* handle pattern_syntax and groks */
	for _, pattern := range n.SubGroks {
		n.Logger.Tracef("Adding subpattern '%s' : '%s'", pattern.Key, pattern.Value)
		if err = pctx.Grok.Add(pattern.Key.(string), pattern.Value.(string)); err != nil {
			if errors.Is(err, grokky.ErrAlreadyExist) {
				n.Logger.Warningf("grok '%s' already registred", pattern.Key)
				continue
			}
			n.Logger.Errorf("Unable to compile subpattern %s : %v", pattern.Key, err)
			return err
		}
	}

	/* load grok by name or compile in-place */
	if n.Grok.RegexpName != "" {
		n.Logger.Tracef("+ Regexp Compilation '%s'", n.Grok.RegexpName)
		n.Grok.RunTimeRegexp, err = pctx.Grok.Get(n.Grok.RegexpName)
		if err != nil {
			return fmt.Errorf("unable to find grok '%s' : %v", n.Grok.RegexpName, err)
		}
		if n.Grok.RunTimeRegexp == nil {
			return fmt.Errorf("empty grok '%s'", n.Grok.RegexpName)
		}
		n.Logger.Tracef("%s regexp: %s", n.Grok.RegexpName, n.Grok.RunTimeRegexp.String())
		valid = true
	} else if n.Grok.RegexpValue != "" {
		if strings.HasSuffix(n.Grok.RegexpValue, "\n") {
			n.Logger.Debugf("Beware, pattern ends with \\n : '%s'", n.Grok.RegexpValue)
		}
		n.Grok.RunTimeRegexp, err = pctx.Grok.Compile(n.Grok.RegexpValue)
		if err != nil {
			return fmt.Errorf("failed to compile grok '%s': %v", n.Grok.RegexpValue, err)
		}
		if n.Grok.RunTimeRegexp == nil {
			// We shouldn't be here because compilation succeeded, so regexp shouldn't be nil
			return fmt.Errorf("grok compilation failure: %s", n.Grok.RegexpValue)
		}
		n.Logger.Tracef("%s regexp : %s", n.Grok.RegexpValue, n.Grok.RunTimeRegexp.String())
		valid = true
	}

	/*if grok source is an expression*/
	if n.Grok.ExpValue != "" {
		n.Grok.RunTimeValue, err = expr.Compile(n.Grok.ExpValue,
			exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		if err != nil {
			return fmt.Errorf("while compiling grok's expression: %w", err)
		}
	}

	/* load grok statics */
	//compile expr statics if present
	for idx := range n.Grok.Statics {
		if n.Grok.Statics[idx].ExpValue != "" {
			n.Grok.Statics[idx].RunTimeValue, err = expr.Compile(n.Grok.Statics[idx].ExpValue,
				exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
			if err != nil {
				return err
			}
		}
		valid = true
	}

	/* load data capture (stash) */
	for i, stash := range n.Stash {
		n.Stash[i].ValueExpression, err = expr.Compile(stash.Value,
			exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		if err != nil {
			return fmt.Errorf("while compiling stash value expression: %w", err)
		}

		n.Stash[i].KeyExpression, err = expr.Compile(stash.Key,
			exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		if err != nil {
			return fmt.Errorf("while compiling stash key expression: %w", err)
		}

		n.Stash[i].TTLVal, err = time.ParseDuration(stash.TTL)
		if err != nil {
			return fmt.Errorf("while parsing stash ttl: %w", err)
		}

		logLvl := n.Logger.Logger.GetLevel()
		//init the cache, does it make sense to create it here just to be sure everything is fine ?
		if err = cache.CacheInit(cache.CacheCfg{
			Size:     n.Stash[i].MaxMapSize,
			TTL:      n.Stash[i].TTLVal,
			Name:     n.Stash[i].Name,
			Strategy: n.Stash[i].Strategy,
			LogLevel: &logLvl,
		}); err != nil {
			return fmt.Errorf("while initializing cache: %w", err)
		}
	}

	/* compile leafs if present */
	for idx := range n.LeavesNodes {
		if n.LeavesNodes[idx].Name == "" {
			n.LeavesNodes[idx].Name = fmt.Sprintf("child-%s", n.Name)
		}
		/*propagate debug/stats to child nodes*/
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
	for idx := range n.Statics {
		if n.Statics[idx].ExpValue != "" {
			n.Statics[idx].RunTimeValue, err = expr.Compile(n.Statics[idx].ExpValue, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
			if err != nil {
				n.Logger.Errorf("Statics Compilation failed %v.", err)
				return err
			}
		}
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
		return fmt.Errorf("Node is empty")
	}

	if err := n.validate(pctx, ectx); err != nil {
		return err
	}

	return nil
}
