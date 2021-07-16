package csplugin

import (
	"context"

	plugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

type Notifier interface {
	Notify(ctx context.Context, notification *Notification) (*Empty, error)
	Configure(ctx context.Context, config *Config) (*Empty, error)
}

type NotifierPlugin struct {
	plugin.Plugin
	Impl Notifier
}

type GRPCClient struct{ client NotifierClient }

func (m *GRPCClient) Notify(ctx context.Context, notification *Notification) (*Empty, error) {
	_, err := m.client.Notify(
		context.Background(), &Notification{Text: notification.Text, Name: notification.Name},
	)
	return &Empty{}, err
}

func (m *GRPCClient) Configure(ctx context.Context, config *Config) (*Empty, error) {
	_, err := m.client.Configure(
		context.Background(), &Config{Config: config.Config},
	)
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
