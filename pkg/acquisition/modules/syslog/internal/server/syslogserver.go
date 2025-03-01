package syslogserver

import (
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

type SyslogServer struct {
	listenAddr    string
	port          int
	channel       chan SyslogMessage
	udpConn       *net.UDPConn
	Logger        *log.Entry
	MaxMessageLen int
}

type SyslogMessage struct {
	Message []byte
	Client  string
}

func (s *SyslogServer) Listen(listenAddr string, port int) error {
	s.listenAddr = listenAddr
	s.port = port
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", s.listenAddr, s.port))
	if err != nil {
		return fmt.Errorf("could not resolve addr %s: %w", s.listenAddr, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("could not listen on port %d: %w", s.port, err)
	}
	s.Logger.Debugf("listening on %s:%d", s.listenAddr, s.port)
	s.udpConn = udpConn

	err = s.udpConn.SetReadDeadline(time.Now().UTC().Add(100 * time.Millisecond))
	if err != nil {
		return fmt.Errorf("could not set read deadline on UDP socket: %w", err)
	}
	return nil
}

func (s *SyslogServer) SetChannel(c chan SyslogMessage) {
	s.channel = c
}

func (s *SyslogServer) StartServer() *tomb.Tomb {
	t := tomb.Tomb{}

	t.Go(func() error {
		for {
			select {
			case <-t.Dying():
				s.Logger.Info("Syslog server tomb is dying")
				err := s.KillServer()
				return err
			default:
				//RFC3164 says 1024 bytes max
				//RFC5424 says 480 bytes minimum, and should support up to 2048 bytes
				b := make([]byte, s.MaxMessageLen)
				n, addr, err := s.udpConn.ReadFrom(b)
				if err != nil && !strings.Contains(err.Error(), "i/o timeout") {
					s.Logger.Errorf("error while reading from socket : %s", err)
					s.udpConn.Close()
					return err
				}
				if err == nil {
					s.channel <- SyslogMessage{Message: b[:n], Client: strings.Split(addr.String(), ":")[0]}
				}
				err = s.udpConn.SetReadDeadline(time.Now().UTC().Add(100 * time.Millisecond))
				if err != nil {
					return err
				}
			}
		}
	})
	return &t
}

func (s *SyslogServer) KillServer() error {
	err := s.udpConn.Close()
	if err != nil {
		return fmt.Errorf("could not close UDP connection: %w", err)
	}
	close(s.channel)
	return nil
}
