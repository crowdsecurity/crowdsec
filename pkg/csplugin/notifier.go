package csplugin

import (
	"context"
	"errors"

	plugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/crowdsecurity/crowdsec/pkg/protobufs"
)

type NotifierPlugin struct {
	plugin.Plugin
	Impl protobufs.NotifierServer
}

type GRPCClient struct{
	protobufs.UnimplementedNotifierServer
	client protobufs.NotifierClient 
}

func (m *GRPCClient) Notify(ctx context.Context, notification *protobufs.Notification) (*protobufs.Empty, error) {
	done := make(chan error)
	go func() {
		_, err := m.client.Notify(
			ctx, &protobufs.Notification{Text: notification.Text, Name: notification.Name},
		)
		done <- err
	}()
	select {
	case err := <-done:
		return &protobufs.Empty{}, err

	case <-ctx.Done():
		return &protobufs.Empty{}, errors.New("timeout exceeded")
	}
}

func (m *GRPCClient) Configure(ctx context.Context, config *protobufs.Config) (*protobufs.Empty, error) {
	_, err := m.client.Configure(ctx, config)
	return &protobufs.Empty{}, err
}

type GRPCServer struct {
	Impl protobufs.NotifierServer
}

func (p *NotifierPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	protobufs.RegisterNotifierServer(s, p.Impl)
	return nil
}

func (p *NotifierPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: protobufs.NewNotifierClient(c)}, nil
}
