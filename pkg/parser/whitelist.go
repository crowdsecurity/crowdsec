package parser

import (
	"net"

	"github.com/antonmedv/expr/vm"
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

type ExprWhitelist struct {
	Filter *vm.Program
}
