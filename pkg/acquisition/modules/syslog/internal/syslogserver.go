package syslogserver

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
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
		return errors.Wrapf(err, "could not resolve addr %s", s.listenAddr)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return errors.Wrapf(err, "could not listen on port %d", s.port)
	}
	s.Logger.Debugf("listening on %s:%d", s.listenAddr, s.port)
	s.udpConn = udpConn
	err = s.udpConn.SetReadBuffer(s.MaxMessageLen) // FIXME probably
	if err != nil {
		return errors.Wrap(err, "could not set readbuffer on UDP socket")
	}
	err = s.udpConn.SetReadDeadline(time.Now().UTC().Add(100 * time.Millisecond))
	if err != nil {
		return errors.Wrap(err, "could not set read deadline on UDP socket")
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
				s.Logger.Info("syslog server tomb is dying")
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
		return errors.Wrap(err, "could not close UDP connection")
	}
	return nil
}
