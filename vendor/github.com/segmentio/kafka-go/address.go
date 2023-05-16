package kafka

import (
	"net"
	"strings"
)

// TCP constructs an address with the network set to "tcp".
func TCP(address ...string) net.Addr { return makeNetAddr("tcp", address) }

func makeNetAddr(network string, addresses []string) net.Addr {
	switch len(addresses) {
	case 0:
		return nil // maybe panic instead?
	case 1:
		return makeAddr(network, addresses[0])
	default:
		return makeMultiAddr(network, addresses)
	}
}

func makeAddr(network, address string) net.Addr {
	return &networkAddress{
		network: network,
		address: canonicalAddress(address),
	}
}

func makeMultiAddr(network string, addresses []string) net.Addr {
	multi := make(multiAddr, len(addresses))
	for i, address := range addresses {
		multi[i] = makeAddr(network, address)
	}
	return multi
}

type networkAddress struct {
	network string
	address string
}

func (a *networkAddress) Network() string { return a.network }

func (a *networkAddress) String() string { return a.address }

type multiAddr []net.Addr

func (m multiAddr) Network() string { return m.join(net.Addr.Network) }

func (m multiAddr) String() string { return m.join(net.Addr.String) }

func (m multiAddr) join(f func(net.Addr) string) string {
	switch len(m) {
	case 0:
		return ""
	case 1:
		return f(m[0])
	}
	s := make([]string, len(m))
	for i, a := range m {
		s[i] = f(a)
	}
	return strings.Join(s, ",")
}
