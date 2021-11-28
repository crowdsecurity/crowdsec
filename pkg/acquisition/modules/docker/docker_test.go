package dockeracquisition

import (
	"fmt"
	"net"
	"testing"
)

func TestConfigure(t *testing.T) {

}

func writeToSyslog(logs []string) {
	conn, err := net.Dial("udp", "127.0.0.1:4242")
	if err != nil {
		fmt.Printf("could not establish connection to syslog server : %s", err)
		return
	}
	for _, log := range logs {
		fmt.Fprint(conn, log)
	}
}

func TestStreamingAcquisition(t *testing.T) {

}
