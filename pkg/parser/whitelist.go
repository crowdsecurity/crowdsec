package parser

import (
	"net"

	"github.com/antonmedv/expr/vm"

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
}

// returns true if the whitelist has at least one IP or CIDR
func (W Whitelist) ContainsIPLists() bool {
	return len(W.B_Ips) > 0 || len(W.B_Cidrs) > 0
}

type ExprWhitelist struct {
	Filter       *vm.Program
	ExprDebugger *exprhelpers.ExprDebugger // used to debug expression by printing the content of each variable of the expression
}
