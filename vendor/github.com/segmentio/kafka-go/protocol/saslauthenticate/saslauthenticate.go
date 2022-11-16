package saslauthenticate

import (
	"encoding/binary"
	"io"

	"github.com/segmentio/kafka-go/protocol"
)

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	AuthBytes []byte `kafka:"min=v0,max=v1"`
}

func (r *Request) RawExchange(rw io.ReadWriter) (protocol.Message, error) {
	if err := r.writeTo(rw); err != nil {
		return nil, err
	}
	return r.readResp(rw)
}

func (*Request) Required(versions map[protocol.ApiKey]int16) bool {
	const v0 = 0
	return versions[protocol.SaslHandshake] == v0
}

func (r *Request) writeTo(w io.Writer) error {
	size := len(r.AuthBytes) + 4
	buf := make([]byte, size)
	binary.BigEndian.PutUint32(buf[:4], uint32(len(r.AuthBytes)))
	copy(buf[4:], r.AuthBytes)
	_, err := w.Write(buf)
	return err
}

func (r *Request) readResp(read io.Reader) (protocol.Message, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(read, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int32(binary.BigEndian.Uint32(lenBuf[:]))
	data := make([]byte, respLen)

	if _, err := io.ReadFull(read, data[:]); err != nil {
		return nil, err
	}
	return &Response{
		AuthBytes: data,
	}, nil
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.SaslAuthenticate }

type Response struct {
	ErrorCode         int16  `kafka:"min=v0,max=v1"`
	ErrorMessage      string `kafka:"min=v0,max=v1,nullable"`
	AuthBytes         []byte `kafka:"min=v0,max=v1"`
	SessionLifetimeMs int64  `kafka:"min=v1,max=v1"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.SaslAuthenticate }

var _ protocol.RawExchanger = (*Request)(nil)
