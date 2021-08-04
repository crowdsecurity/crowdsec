package main

import (
	"context"

	plugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// Handshake is a common handshake that is shared by plugin and host.
var Handshake = plugin.HandshakeConfig{
	// This isn't required when using VersionedPlugins
	ProtocolVersion:  1,
	MagicCookieKey:   "BASIC_PLUGIN",
	MagicCookieValue: "hello",
}

// KV is the interface that we're exposing as a plugin.
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

// Here is the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	// This is the real implementation
	Impl Notifier
}

func (p *NotifierPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	RegisterNotifierServer(s, p.Impl)
	return nil
}

func (p *NotifierPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewNotifierClient(c)}, nil
}
