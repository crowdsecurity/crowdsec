package syslogserver

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type SyslogServer struct {
	conn          *net.UDPConn
	listener      net.Listener
	Logger        *log.Entry
	MaxMessageLen int
	Proto         string
}

type SyslogMessage struct {
	Message []byte
	Client  string
}

func (s *SyslogServer) Listen(listenAddr string, port int, proto string) error {
	addr := net.JoinHostPort(listenAddr, strconv.Itoa(port))
	protocol := strings.ToLower(strings.TrimSpace(proto))
	if protocol == "" {
		protocol = "udp"
	}

	s.Proto = protocol

	switch protocol {
	case "udp":
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return fmt.Errorf("could not resolve addr %s: %w", listenAddr, err)
		}

		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("could not listen on port %d: %w", port, err)
		}

		s.Logger.Debugf("listening on %s", addr)
		s.conn = udpConn
		return nil
	case "tcp":
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("could not listen on %s: %w", addr, err)
		}

		s.Logger.Debugf("listening on %s", addr)
		s.listener = listener
		return nil
	default:
		return fmt.Errorf("unsupported protocol %s", protocol)
	}
}

func (s *SyslogServer) Serve(ctx context.Context, msgChan chan SyslogMessage) error {
	go func() {
		<-ctx.Done()
		if s.conn != nil {
			// closing the socket unblocks ReadFrom()
			s.conn.Close()
		}
		if s.listener != nil {
			_ = s.listener.Close()
		}
	}()

	if s.Proto == "tcp" {
		return s.serveTCP(ctx, msgChan)
	}

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

func (s *SyslogServer) serveTCP(ctx context.Context, msgChan chan SyslogMessage) error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil //nolint:nilerr
			}
			return fmt.Errorf("accepting connection: %w", err)
		}

		go s.handleConn(ctx, conn, msgChan)
	}
}

func (s *SyslogServer) handleConn(ctx context.Context, conn net.Conn, msgChan chan SyslogMessage) {
	defer conn.Close()

	client := strings.Split(conn.RemoteAddr().String(), ":")[0]
	reader := bufio.NewScanner(conn)
	buf := make([]byte, s.MaxMessageLen)
	reader.Buffer(buf, s.MaxMessageLen)

	for reader.Scan() {
		line := append([]byte{}, reader.Bytes()...)
		msg := SyslogMessage{Message: line, Client: client}

		select {
		case msgChan <- msg:
		case <-ctx.Done():
			return
		}
	}

	if err := reader.Err(); err != nil && ctx.Err() == nil {
		s.Logger.WithField("client", client).WithError(err).Debug("tcp read error")
	}
}

func (s *SyslogServer) KillServer() error {
	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			return fmt.Errorf("could not close UDP connection: %w", err)
		}
	}

	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			return fmt.Errorf("could not close TCP listener: %w", err)
		}
	}

	return nil
}
