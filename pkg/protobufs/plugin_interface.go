package protobufs

import (
	"context"

	plugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

type Notifier interface {
	Notify(ctx context.Context, notification *Notification) (*Empty, error)
	Configure(ctx context.Context, config *Config) (*Empty, error)
}

// This is the implementation of plugin.NotifierPlugin so we can serve/consume this.
type NotifierPlugin struct {
	// GRPCPlugin must still implement the Plugin interface
	plugin.Plugin
	// Concrete implementation, written in Go. This is only used for plugins
	// that are written in Go.
	Impl Notifier
}

type GRPCClient struct{ client NotifierClient }

func (m *GRPCClient) Notify(ctx context.Context, notification *Notification) (*Empty, error) {
	_, err := m.client.Notify(context.Background(), notification)
	return &Empty{}, err
}

func (m *GRPCClient) Configure(ctx context.Context, config *Config) (*Empty, error) {
	_, err := m.client.Configure(context.Background(), config)
	return &Empty{}, err
}

type GRPCServer struct {
	Impl Notifier
}

func (p *NotifierPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	RegisterNotifierServer(s, p.Impl)
	return nil
}

func (p *NotifierPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewNotifierClient(c)}, nil
}
