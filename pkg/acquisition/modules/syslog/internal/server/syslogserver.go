package syslogserver

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type SyslogServer struct {
	conn          *net.UDPConn
	Logger        *log.Entry
	MaxMessageLen int
}

type SyslogMessage struct {
	Message []byte
	Client  string
}

func (s *SyslogServer) Listen(listenAddr string, port int) error {
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(listenAddr, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("could not resolve addr %s: %w", listenAddr, err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("could not listen on port %d: %w", port, err)
	}

	s.Logger.Debugf("listening on %s:%d", listenAddr, port)
	s.conn = udpConn

	return nil
}

func (s *SyslogServer) Serve(ctx context.Context, msgChan chan SyslogMessage) error {
	go func() {
		<-ctx.Done()
		// closing the socket unblocks ReadFrom()
		s.conn.Close()
	}()

	// RFC3164 says 1024 bytes max
	// RFC5424 says 480 bytes minimum, and should support up to 2048 bytes
	buf := make([]byte, s.MaxMessageLen)

	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil //nolint:nilerr  // context cancelation is not a failure
			}

			return fmt.Errorf("reading from socket: %w", err)
		}

		msg := SyslogMessage{Message: buf[:n], Client: strings.Split(addr.String(), ":")[0]}

		select {
		case msgChan <- msg:
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *SyslogServer) KillServer() error {
	if err := s.conn.Close(); err != nil {
		return fmt.Errorf("could not close UDP connection: %w", err)
	}

	return nil
}
