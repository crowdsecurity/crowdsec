package syslogserver

import (
	"fmt"
	"net"
	"strings"

	"gopkg.in/tomb.v2"
)

type SyslogServer struct {
	proto        string
	listenAddr   string
	port         int
	tcpListener  *net.TCPListener
	udpConn      *net.UDPConn
	parsingTombs []*tomb.Tomb
	acceptTombs  []*tomb.Tomb
	receiveTombs []*tomb.Tomb
}

func (s *SyslogServer) SetProtocol(proto string) error {
	proto = strings.ToLower(proto)
	if proto != "tcp" && proto != "udp" {
		return fmt.Errorf("protocol must be tcp or udp, got %s", proto)
	}
	s.proto = proto
	return nil
}

func (s *SyslogServer) Listen(listenAddr string, port int) error {
	switch s.proto {
	case "tcp":
		tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", s.listenAddr, s.port))
		if err != nil {
			return err
		}
		tcpListener, err := net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			return err
		}
		s.tcpListener = tcpListener
	case "udp":
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", s.listenAddr, s.port))
		if err != nil {
			return err
		}
		udpConn, err := net.ListenUDP("tcp", udpAddr)
		if err != nil {
			return err
		}
		s.udpConn = udpConn
		s.udpConn.SetReadBuffer(1024 * 8) // FIXME probably
	}
	return nil
}
