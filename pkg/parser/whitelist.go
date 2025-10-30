package parser

import (
	"fmt"
	"net/netip"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Whitelist struct {
	Reason  string   `yaml:"reason,omitempty"`
	Ips     []string `yaml:"ip,omitempty"`
	B_Ips   []netip.Addr
	Cidrs   []string `yaml:"cidr,omitempty"`
	B_Cidrs []netip.Prefix
	Exprs   []string `yaml:"expression,omitempty"`
	B_Exprs []*ExprWhitelist
}

type ExprWhitelist struct {
	Filter *vm.Program
}

func (n *Node) ContainsWLs() bool {
	return n.ContainsIPLists() || n.ContainsExprLists()
}

func (n *Node) ContainsExprLists() bool {
	return len(n.Whitelist.B_Exprs) > 0
}

func (n *Node) ContainsIPLists() bool {
	return len(n.Whitelist.B_Ips) > 0 || len(n.Whitelist.B_Cidrs) > 0
}

func (n *Node) CheckIPsWL(p *pipeline.Event) bool {
	srcs := p.ParseIPSources()
	isWhitelisted := false
	if !n.ContainsIPLists() {
		return isWhitelisted
	}
	n.bumpWhitelistMetric(metrics.NodesWlHits, p)
	for _, src := range srcs {
		if isWhitelisted {
			break
		}
		for _, v := range n.Whitelist.B_Ips {
			if v == src {
				n.Logger.Debugf("Event from [%s] is whitelisted by IP (%s), reason [%s]", src, v, n.Whitelist.Reason)
				isWhitelisted = true
				break
			}
			n.Logger.Tracef("whitelist: %s is not eq [%s]", src, v)
		}
		for _, v := range n.Whitelist.B_Cidrs {
			if v.Contains(src) {
				n.Logger.Debugf("Event from [%s] is whitelisted by CIDR (%s), reason [%s]", src, v, n.Whitelist.Reason)
				isWhitelisted = true
				break
			}
			n.Logger.Tracef("whitelist: %s not in [%s]", src, v)
		}
	}
	if isWhitelisted {
		n.bumpWhitelistMetric(metrics.NodesWlHitsOk, p)
	}
	return isWhitelisted
}

func (n *Node) CheckExprWL(cachedExprEnv map[string]any, p *pipeline.Event) (bool, error) {
	isWhitelisted := false

	if !n.ContainsExprLists() {
		return false, nil
	}
	n.bumpWhitelistMetric(metrics.NodesWlHits, p)
	/* run whitelist expression tests anyway */
	for eidx, e := range n.Whitelist.B_Exprs {
		// if we already know the event is whitelisted, skip the rest of the expressions
		if isWhitelisted {
			break
		}

		output, err := exprhelpers.Run(e.Filter, cachedExprEnv, n.Logger, n.Debug)
		if err != nil {
			n.Logger.Warningf("failed to run whitelist expr : %v", err)
			n.Logger.Debug("Event leaving node : ko")
			return isWhitelisted, err
		}
		switch out := output.(type) {
		case bool:
			if out {
				n.Logger.Debugf("Event is whitelisted by expr, reason [%s]", n.Whitelist.Reason)
				isWhitelisted = true
			}
		default:
			n.Logger.Errorf("unexpected type %t (%v) while running '%s'", output, output, n.Whitelist.Exprs[eidx])
		}
	}
	if isWhitelisted {
		n.bumpWhitelistMetric(metrics.NodesWlHitsOk, p)
	}
	return isWhitelisted, nil
}

func (n *Node) CompileWLs() (bool, error) {
	for _, v := range n.Whitelist.Ips {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return false, fmt.Errorf("parsing whitelist: %w", err)
		}

		n.Whitelist.B_Ips = append(n.Whitelist.B_Ips, addr)
		n.Logger.Debugf("adding ip %s to whitelists", addr)
	}

	for _, v := range n.Whitelist.Cidrs {
		tnet, err := netip.ParsePrefix(v)
		if err != nil {
			return false, fmt.Errorf("parsing whitelist: %w", err)
		}
		n.Whitelist.B_Cidrs = append(n.Whitelist.B_Cidrs, tnet)
		n.Logger.Debugf("adding cidr %s to whitelists", tnet)
	}

	for _, filter := range n.Whitelist.Exprs {
		var err error
		expression := &ExprWhitelist{}
		expression.Filter, err = expr.Compile(filter, exprhelpers.GetExprOptions(map[string]any{"evt": &pipeline.Event{}})...)
		if err != nil {
			return false, fmt.Errorf("unable to compile whitelist expression '%s' : %v", filter, err)
		}
		n.Whitelist.B_Exprs = append(n.Whitelist.B_Exprs, expression)
		n.Logger.Debugf("adding expression %s to whitelists", filter)
	}
	return n.ContainsWLs(), nil
}

func (n *Node) bumpWhitelistMetric(counter *prometheus.CounterVec, p *pipeline.Event) {
	// better safe than sorry
	acquisType := p.Line.Labels["type"]
	if acquisType == "" {
		acquisType = "unknown"
	}

	labels := prometheus.Labels{
		"source":      p.Line.Src,
		"type":        p.Line.Module,
		"name":        n.Name,
		"reason":      n.Whitelist.Reason,
		"stage":       p.Stage,
		"acquis_type": acquisType,
	}

	counter.With(labels).Inc()
}
