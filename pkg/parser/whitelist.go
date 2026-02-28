package parser

import (
	"fmt"
	"net/netip"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/gaissmai/bart"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Whitelist struct {
	Reason  string   `yaml:"reason,omitempty"`
	Ips     []string `yaml:"ip,omitempty"`
	Cidrs   []string `yaml:"cidr,omitempty"`
	B_Trie  *bart.Lite // BART lite table for IP/CIDR lookups
	Exprs   []string   `yaml:"expression,omitempty"`
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
	return n.Whitelist.B_Trie != nil && n.Whitelist.B_Trie.Size() > 0
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
		// Use BART lite trie for fast lookup
		if n.Whitelist.B_Trie.Contains(src) {
			n.Logger.Debugf("Event from [%s] is whitelisted, reason [%s]", src, n.Whitelist.Reason)
			isWhitelisted = true
		} else {
			n.Logger.Tracef("whitelist: %s not in allowlist", src)
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
	// Initialize BART lite trie if we have IPs or CIDRs
	if len(n.Whitelist.Ips) > 0 || len(n.Whitelist.Cidrs) > 0 {
		n.Whitelist.B_Trie = new(bart.Lite)
	}

	// Convert IPs to /32 (IPv4) or /128 (IPv6) CIDR format and insert into trie
	for _, v := range n.Whitelist.Ips {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return false, fmt.Errorf("parsing whitelist: %w", err)
		}

		// Convert IP to /32 (IPv4) or /128 (IPv6) CIDR prefix
		var prefix netip.Prefix
		if addr.Is4() {
			prefix = netip.PrefixFrom(addr, 32)
		} else {
			prefix = netip.PrefixFrom(addr, 128)
		}

		n.Whitelist.B_Trie.Insert(prefix)
		n.Logger.Debugf("adding ip %s (as %s) to whitelists", addr, prefix)
	}

	// Insert CIDR ranges into trie
	for _, v := range n.Whitelist.Cidrs {
		prefix, err := netip.ParsePrefix(v)
		if err != nil {
			return false, fmt.Errorf("parsing whitelist: %w", err)
		}
		n.Whitelist.B_Trie.Insert(prefix)
		n.Logger.Debugf("adding cidr %s to whitelists", prefix)
	}

	// Compile expression whitelists
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
