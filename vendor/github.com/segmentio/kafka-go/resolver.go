package kafka

import (
	"context"
	"net"
)

// The Resolver interface is used as an abstraction to provide service discovery
// of the hosts of a kafka cluster.
type Resolver interface {
	// LookupHost looks up the given host using the local resolver.
	// It returns a slice of that host's addresses.
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
}

// BrokerResolver is an interface implemented by types that translate host
// names into a network address.
//
// This resolver is not intended to be a general purpose interface. Instead,
// it is tailored to the particular needs of the kafka protocol, with the goal
// being to provide a flexible mechanism for extending broker name resolution
// while retaining context that is specific to interacting with a kafka cluster.
//
// Resolvers must be safe to use from multiple goroutines.
type BrokerResolver interface {
	// Returns the IP addresses of the broker passed as argument.
	LookupBrokerIPAddr(ctx context.Context, broker Broker) ([]net.IPAddr, error)
}

// NewBrokerResolver constructs a Resolver from r.
//
// If r is nil, net.DefaultResolver is used instead.
func NewBrokerResolver(r *net.Resolver) BrokerResolver {
	return brokerResolver{r}
}

type brokerResolver struct {
	*net.Resolver
}

func (r brokerResolver) LookupBrokerIPAddr(ctx context.Context, broker Broker) ([]net.IPAddr, error) {
	ipAddrs, err := r.LookupIPAddr(ctx, broker.Host)
	if err != nil {
		return nil, err
	}

	if len(ipAddrs) == 0 {
		return nil, &net.DNSError{
			Err:         "no addresses were returned by the resolver",
			Name:        broker.Host,
			IsTemporary: true,
			IsNotFound:  true,
		}
	}

	return ipAddrs, nil
}
