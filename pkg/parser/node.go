package parser

import (
	"fmt"
	"net"
	"strings"

	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/grokky"
	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"

	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
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
	Rerferences []string `yaml:"references,omitempty"`
	//if debug is present in the node, keep its specific Logger in runtime structure
	Logger *log.Entry `yaml:"-"`
	//This is mostly a hack to make writting less repetive.
	//relying on stage, we know which field to parse, and we
	//can as well promote log to next stage on success
	Stage string `yaml:"stage,omitempty"`
	//OnSuccess allows to tag a node to be able to move log to next stage on success
	OnSuccess string `yaml:"onsuccess,omitempty"`
	rn        string //this is only for us in debug, a random generated name for each node
	//Filter is executed at runtime (with current log line as context)
	//and must succeed or node is exited
	Filter        string                    `yaml:"filter,omitempty"`
	RunTimeFilter *vm.Program               `yaml:"-" json:"-"` //the actual compiled filter
	ExprDebugger  *exprhelpers.ExprDebugger `yaml:"-" json:"-"` //used to debug expression by printing the content of each variable of the expression
	//If node has leafs, execute all of them until one asks for a 'break'
	LeavesNodes []Node `yaml:"nodes,omitempty"`
	//Flag used to describe when to 'break' or return an 'error'
	EnrichFunctions EnricherCtx

	/* If the node is actually a leaf, it can have : grok, enrich, statics */
	//pattern_syntax are named grok patterns that are re-utilised over several grok patterns
	SubGroks yaml.MapSlice `yaml:"pattern_syntax,omitempty"`

	//Holds a grok pattern
	Grok types.GrokPattern `yaml:"grok,omitempty"`
	//Statics can be present in any type of node and is executed last
	Statics []types.ExtraField `yaml:"statics,omitempty"`
	//Whitelists
	Whitelist types.Whitelist     `yaml:"whitelist,omitempty"`
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
	return nil
}

func (n *Node) process(p *types.Event, ctx UnixParserCtx) (bool, error) {
	var NodeState bool
	var NodeHasOKGrok bool
	clog := n.Logger

	clog.Tracef("Event entering node")
	if n.RunTimeFilter != nil {
		//Evaluate node's filter
		output, err := expr.Run(n.RunTimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": p}))
		if err != nil {
			clog.Warningf("failed to run filter : %v", err)
			clog.Debugf("Event leaving node : ko")
			return false, nil
		}

		switch out := output.(type) {
		case bool:
			if n.Debug {
				n.ExprDebugger.Run(clog, out, exprhelpers.GetExprEnv(map[string]interface{}{"evt": p}))
			}
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
	isWhitelisted := false
	hasWhitelist := false
	var srcs []net.IP
	/*overflow and log don't hold the source ip in the same field, should be changed */
	/* perform whitelist checks for ips, cidr accordingly */
	/* TODO move whitelist elsewhere */
	if p.Type == types.LOG {
		if _, ok := p.Meta["source_ip"]; ok {
			srcs = append(srcs, net.ParseIP(p.Meta["source_ip"]))
		}
	} else if p.Type == types.OVFLW {
		for k := range p.Overflow.Sources {
			srcs = append(srcs, net.ParseIP(k))
		}
	}
	for _, src := range srcs {
		if isWhitelisted {
			break
		}
		for _, v := range n.Whitelist.B_Ips {
			if v.Equal(src) {
				clog.Debugf("Event from [%s] is whitelisted by IP (%s), reason [%s]", src, v, n.Whitelist.Reason)
				isWhitelisted = true
			} else {
				clog.Tracef("whitelist: %s is not eq [%s]", src, v)
			}
			hasWhitelist = true
		}
		for _, v := range n.Whitelist.B_Cidrs {
			if v.Contains(src) {
				clog.Debugf("Event from [%s] is whitelisted by CIDR (%s), reason [%s]", src, v, n.Whitelist.Reason)
				isWhitelisted = true
			} else {
				clog.Tracef("whitelist: %s not in [%s]", src, v)
			}
			hasWhitelist = true
		}
	}

	if isWhitelisted {
		p.Whitelisted = true
	}
	/* run whitelist expression tests anyway */
	for eidx, e := range n.Whitelist.B_Exprs {
		output, err := expr.Run(e.Filter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": p}))
		if err != nil {
			clog.Warningf("failed to run whitelist expr : %v", err)
			clog.Debugf("Event leaving node : ko")
			return false, nil
		}
		switch out := output.(type) {
		case bool:
			if n.Debug {
				e.ExprDebugger.Run(clog, out, exprhelpers.GetExprEnv(map[string]interface{}{"evt": p}))
			}
			if out {
				clog.Debugf("Event is whitelisted by expr, reason [%s]", n.Whitelist.Reason)
				p.Whitelisted = true
				isWhitelisted = true
			}
			hasWhitelist = true
		default:
			log.Errorf("unexpected type %t (%v) while running '%s'", output, output, n.Whitelist.Exprs[eidx])
		}
	}
	if isWhitelisted {
		p.WhitelistReason = n.Whitelist.Reason
		/*huglily wipe the ban order if the event is whitelisted and it's an overflow */
		if p.Type == types.OVFLW { /*don't do this at home kids */
			ips := []string{}
			for _, src := range srcs {
				ips = append(ips, src.String())
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
			output, err := expr.Run(n.Grok.RunTimeValue, exprhelpers.GetExprEnv(map[string]interface{}{"evt": p}))
			if err != nil {
				clog.Warningf("failed to run RunTimeValue : %v", err)
				NodeState = false
			}
			switch out := output.(type) {
			case string:
				gstr = out
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
			/*tag explicitely that the *current* node had a successful grok pattern. it's important to know success state*/
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
				clog.Fatalf("(%s) Failed to process statics : %v", n.rn, err)
			}
		} else {
			//grok failed, node failed
			clog.Debugf("+ Grok '%s' didn't return data on '%s'", groklabel, gstr)
			NodeState = false
		}

	} else {
		clog.Tracef("! No grok pattern : %p", n.Grok.RunTimeRegexp)
	}

	//Iterate on leafs
	if len(n.LeavesNodes) > 0 {
		for _, leaf := range n.LeavesNodes {
			ret, err := leaf.process(p, ctx)
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
			} else {
				/*
					If the parent node has a successful grok pattern, it's state will stay successfull even if one or more chil fails.
					If the parent node is a skeleton node (no grok pattern), then at least one child must be successful for it to be a success.
				*/
				if !NodeHasOKGrok {
					NodeState = false
				}
			}
		}
	}
	/*todo : check if a node made the state change ?*/
	/* should the childs inherit the on_success behaviour */

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
		Please kill me. this is to apply statics when the node *has* whitelists that successfully matched the node.
	*/
	if hasWhitelist && isWhitelisted && len(n.Statics) > 0 || len(n.Statics) > 0 && !hasWhitelist {
		clog.Debugf("+ Processing %d statics", len(n.Statics))
		// if all else is good in whitelist, process node's statics
		err := n.ProcessStatics(n.Statics, p)
		if err != nil {
			clog.Fatalf("Failed to process statics : %v", err)
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
		var clog = logrus.New()
		if err := types.ConfigureLogger(clog); err != nil {
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
		n.RunTimeFilter, err = expr.Compile(n.Filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
		if err != nil {
			return fmt.Errorf("compilation of '%s' failed: %v", n.Filter, err)
		}

		if n.Debug {
			n.ExprDebugger, err = exprhelpers.NewDebugger(n.Filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
			if err != nil {
				log.Errorf("unable to build debug filter for '%s' : %s", n.Filter, err)
			}
		}

	}

	/* handle pattern_syntax and groks */
	for _, pattern := range n.SubGroks {
		n.Logger.Tracef("Adding subpattern '%s' : '%s'", pattern.Key, pattern.Value)
		if err := pctx.Grok.Add(pattern.Key.(string), pattern.Value.(string)); err != nil {
			if err == grokky.ErrAlreadyExist {
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
			return fmt.Errorf("Unable to find grok '%s' : %v", n.Grok.RegexpName, err)
		}
		if n.Grok.RunTimeRegexp == nil {
			return fmt.Errorf("Empty grok '%s'", n.Grok.RegexpName)
		}
		n.Logger.Tracef("%s regexp: %s", n.Grok.RegexpName, n.Grok.RunTimeRegexp.Regexp.String())
		valid = true
	} else if n.Grok.RegexpValue != "" {
		if strings.HasSuffix(n.Grok.RegexpValue, "\n") {
			n.Logger.Debugf("Beware, pattern ends with \\n : '%s'", n.Grok.RegexpValue)
		}
		n.Grok.RunTimeRegexp, err = pctx.Grok.Compile(n.Grok.RegexpValue)
		if err != nil {
			return fmt.Errorf("Failed to compile grok '%s': %v\n", n.Grok.RegexpValue, err)
		}
		if n.Grok.RunTimeRegexp == nil {
			// We shouldn't be here because compilation succeeded, so regexp shouldn't be nil
			return fmt.Errorf("Grok compilation failure: %s", n.Grok.RegexpValue)
		}
		n.Logger.Tracef("%s regexp : %s", n.Grok.RegexpValue, n.Grok.RunTimeRegexp.Regexp.String())
		valid = true
	}

	/*if grok source is an expression*/
	if n.Grok.ExpValue != "" {
		n.Grok.RunTimeValue, err = expr.Compile(n.Grok.ExpValue,
			expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
		if err != nil {
			return errors.Wrap(err, "while compiling grok's expression")
		}
	}

	/* load grok statics */
	if len(n.Grok.Statics) > 0 {
		//compile expr statics if present
		for idx := range n.Grok.Statics {
			if n.Grok.Statics[idx].ExpValue != "" {
				n.Grok.Statics[idx].RunTimeValue, err = expr.Compile(n.Grok.Statics[idx].ExpValue,
					expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
				if err != nil {
					return err
				}
			}
		}
		valid = true
	}
	/* compile leafs if present */
	if len(n.LeavesNodes) > 0 {
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
		}
		valid = true
	}
	/* load statics if present */
	for idx := range n.Statics {
		if n.Statics[idx].ExpValue != "" {
			n.Statics[idx].RunTimeValue, err = expr.Compile(n.Statics[idx].ExpValue, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
			if err != nil {
				n.Logger.Errorf("Statics Compilation failed %v.", err)
				return err
			}
		}
		valid = true
	}

	/* compile whitelists if present */
	for _, v := range n.Whitelist.Ips {
		n.Whitelist.B_Ips = append(n.Whitelist.B_Ips, net.ParseIP(v))
		n.Logger.Debugf("adding ip %s to whitelists", net.ParseIP(v))
		valid = true
	}
	for _, v := range n.Whitelist.Cidrs {
		_, tnet, err := net.ParseCIDR(v)
		if err != nil {
			n.Logger.Fatalf("Unable to parse cidr whitelist '%s' : %v.", v, err)
		}
		n.Whitelist.B_Cidrs = append(n.Whitelist.B_Cidrs, tnet)
		n.Logger.Debugf("adding cidr %s to whitelists", tnet)
		valid = true
	}
	for _, filter := range n.Whitelist.Exprs {
		expression := &types.ExprWhitelist{}
		expression.Filter, err = expr.Compile(filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
		if err != nil {
			n.Logger.Fatalf("Unable to compile whitelist expression '%s' : %v.", filter, err)
		}
		expression.ExprDebugger, err = exprhelpers.NewDebugger(filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
		if err != nil {
			log.Errorf("unable to build debug filter for '%s' : %s", filter, err)
		}
		n.Whitelist.B_Exprs = append(n.Whitelist.B_Exprs, expression)
		n.Logger.Debugf("adding expression %s to whitelists", filter)
		valid = true
	}

	if !valid {
		/* node is empty, error force return */
		n.Logger.Infof("Node is empty: %s", spew.Sdump(n))
		n.Stage = ""
	}
	if err := n.validate(pctx, ectx); err != nil {
		return err
		//n.logger.Fatalf("Node is invalid : %s", err)
	}
	return nil
}
