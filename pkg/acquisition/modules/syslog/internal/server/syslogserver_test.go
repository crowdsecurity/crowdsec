package syslogserver

import (
	"context"
	"net"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestReceivedMessagesDoNotAliasReadBuffer(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	srv := &SyslogServer{
		MaxMessageLen: 2048,
		Logger:        log.New().WithField("test", true),
	}

	require.NoError(t, srv.Listen("127.0.0.1", 0))

	out := make(chan SyslogMessage)

	go func() {
		_ = srv.Serve(ctx, out)
	}()

	conn, err := net.DialUDP("udp", nil, srv.conn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	defer conn.Close()

	first := []byte("<14>1 first-message")
	second := []byte("<14>1 second-message")

	_, err = conn.Write(first)
	require.NoError(t, err)

	got := <-out

	_, err = conn.Write(second)
	require.NoError(t, err)

	<-out

	require.Equal(t, string(first), string(got.Message))
}
