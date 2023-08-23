package parser

import (
	"fmt"
	"net"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type Whitelist struct {
	Reason  string   `yaml:"reason,omitempty"`
	Ips     []string `yaml:"ip,omitempty"`
	B_Ips   []net.IP
	Cidrs   []string `yaml:"cidr,omitempty"`
	B_Cidrs []*net.IPNet
	Exprs   []string `yaml:"expression,omitempty"`
	B_Exprs []*ExprWhitelist
	Node    *Node `yaml:"-"` // Pointer to the node containing this whitelist
}

func (W Whitelist) ContainsIPLists() bool {
	return len(W.B_Ips) > 0 || len(W.B_Cidrs) > 0
}

func (W Whitelist) ContainsExprLists() bool {
	return len(W.B_Exprs) > 0
}

func (W Whitelist) Check(srcs []net.IP, cachedExprEnv map[string]interface{}) (bool, bool, error) {
	isWhitelisted := false
	hasWhitelist := false
	var err error
	var output interface{}
	if W.ContainsIPLists() {
		for _, src := range srcs {
			if isWhitelisted {
				break
			}
			for _, v := range W.B_Ips {
				if v.Equal(src) {
					W.Node.Logger.Debugf("Event from [%s] is whitelisted by IP (%s), reason [%s]", src, v, W.Reason)
					isWhitelisted = true
					break
				}
				W.Node.Logger.Tracef("whitelist: %s is not eq [%s]", src, v)
			}
			for _, v := range W.B_Cidrs {
				if v.Contains(src) {
					W.Node.Logger.Debugf("Event from [%s] is whitelisted by CIDR (%s), reason [%s]", src, v, W.Reason)
					isWhitelisted = true
					break
				}
				W.Node.Logger.Tracef("whitelist: %s not in [%s]", src, v)
			}
		}
		hasWhitelist = true
	}
	/* run whitelist expression tests anyway */
	for eidx, e := range W.B_Exprs {
		//if we already know the event is whitelisted, skip the rest of the expressions
		if isWhitelisted {
			break
		}
		output, err = expr.Run(e.Filter, cachedExprEnv)
		if err != nil {
			W.Node.Logger.Warningf("failed to run whitelist expr : %v", err)
			W.Node.Logger.Debug("Event leaving node : ko")
			break
		}
		switch out := output.(type) {
		case bool:
			if W.Node.Debug {
				e.ExprDebugger.Run(W.Node.Logger, out, cachedExprEnv)
			}
			if out {
				W.Node.Logger.Debugf("Event is whitelisted by expr, reason [%s]", W.Reason)
				isWhitelisted = true
			}
			hasWhitelist = true
		default:
			W.Node.Logger.Errorf("unexpected type %t (%v) while running '%s'", output, output, W.Exprs[eidx])
		}
	}
	return isWhitelisted, hasWhitelist, err
}

func (W *Whitelist) Compile(n *Node) (bool, error) {
	for _, v := range W.Ips {
		W.B_Ips = append(W.B_Ips, net.ParseIP(v))
		n.Logger.Debugf("adding ip %s to whitelists", net.ParseIP(v))
	}

	for _, v := range W.Cidrs {
		_, tnet, err := net.ParseCIDR(v)
		if err != nil {
			return false, fmt.Errorf("unable to parse cidr whitelist '%s' : %v", v, err)
		}
		W.B_Cidrs = append(W.B_Cidrs, tnet)
		n.Logger.Debugf("adding cidr %s to whitelists", tnet)
	}

	for _, filter := range W.Exprs {
		var err error
		expression := &ExprWhitelist{}
		expression.Filter, err = expr.Compile(filter, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		if err != nil {
			return false, fmt.Errorf("unable to compile whitelist expression '%s' : %v", filter, err)
		}
		expression.ExprDebugger, err = exprhelpers.NewDebugger(filter, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		if err != nil {
			log.Errorf("unable to build debug filter for '%s' : %s", filter, err)
		}
		W.B_Exprs = append(W.B_Exprs, expression)
		n.Logger.Debugf("adding expression %s to whitelists", filter)
	}
	valid := false
	if W.ContainsIPLists() || W.ContainsExprLists() {
		W.Node = n
		valid = true
	}
	return valid, nil
}

type ExprWhitelist struct {
	Filter       *vm.Program
	ExprDebugger *exprhelpers.ExprDebugger // used to debug expression by printing the content of each variable of the expression
}
