package protocol

import (
	"bufio"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

type Conn struct {
	buffer   *bufio.Reader
	conn     net.Conn
	clientID string
	idgen    int32
	versions atomic.Value // map[ApiKey]int16
}

func NewConn(conn net.Conn, clientID string) *Conn {
	return &Conn{
		buffer:   bufio.NewReader(conn),
		conn:     conn,
		clientID: clientID,
	}
}

func (c *Conn) String() string {
	return fmt.Sprintf("kafka://%s@%s->%s", c.clientID, c.LocalAddr(), c.RemoteAddr())
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) Discard(n int) (int, error) {
	return c.buffer.Discard(n)
}

func (c *Conn) Peek(n int) ([]byte, error) {
	return c.buffer.Peek(n)
}

func (c *Conn) Read(b []byte) (int, error) {
	return c.buffer.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) SetVersions(versions map[ApiKey]int16) {
	connVersions := make(map[ApiKey]int16, len(versions))

	for k, v := range versions {
		connVersions[k] = v
	}

	c.versions.Store(connVersions)
}

func (c *Conn) RoundTrip(msg Message) (Message, error) {
	correlationID := atomic.AddInt32(&c.idgen, +1)
	versions, _ := c.versions.Load().(map[ApiKey]int16)
	apiVersion := versions[msg.ApiKey()]

	if p, _ := msg.(PreparedMessage); p != nil {
		p.Prepare(apiVersion)
	}

	if raw, ok := msg.(RawExchanger); ok && raw.Required(versions) {
		return raw.RawExchange(c)
	}

	return RoundTrip(c, apiVersion, correlationID, c.clientID, msg)
}

var (
	_ net.Conn       = (*Conn)(nil)
	_ bufferedReader = (*Conn)(nil)
)
