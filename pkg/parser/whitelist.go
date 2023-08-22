package parser

import (
	"net"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
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

func (W Whitelist) Check(srcs []net.IP, cachedExprEnv map[string]interface{}) (bool, bool) {
	isWhitelisted := false
	hasWhitelist := false
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
		output, err := expr.Run(e.Filter, cachedExprEnv)
		if err != nil {
			W.Node.Logger.Warningf("failed to run whitelist expr : %v", err)
			W.Node.Logger.Debug("Event leaving node : ko")
			return false, false
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
			log.Errorf("unexpected type %t (%v) while running '%s'", output, output, W.Exprs[eidx])
		}
	}
	return isWhitelisted, hasWhitelist
}

type ExprWhitelist struct {
	Filter       *vm.Program
	ExprDebugger *exprhelpers.ExprDebugger // used to debug expression by printing the content of each variable of the expression
}
