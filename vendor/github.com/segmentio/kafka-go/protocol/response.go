package protocol

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

func ReadResponse(r io.Reader, apiKey ApiKey, apiVersion int16) (correlationID int32, msg Message, err error) {
	if i := int(apiKey); i < 0 || i >= len(apiTypes) {
		err = fmt.Errorf("unsupported api key: %d", i)
		return
	}

	t := &apiTypes[apiKey]
	if t == nil {
		err = fmt.Errorf("unsupported api: %s", apiNames[apiKey])
		return
	}

	minVersion := t.minVersion()
	maxVersion := t.maxVersion()

	if apiVersion < minVersion || apiVersion > maxVersion {
		err = fmt.Errorf("unsupported %s version: v%d not in range v%d-v%d", apiKey, apiVersion, minVersion, maxVersion)
		return
	}

	d := &decoder{reader: r, remain: 4}
	size := d.readInt32()

	if err = d.err; err != nil {
		err = dontExpectEOF(err)
		return
	}

	d.remain = int(size)
	correlationID = d.readInt32()
	if err = d.err; err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			// If a Writer/Reader is configured without TLS and connects
			// to a broker expecting TLS the only message we return to the
			// caller is io.ErrUnexpetedEOF which is opaque. This section
			// tries to determine if that's what has happened.
			// We first deconstruct the initial 4 bytes of the message
			// from the size which was read earlier.
			// Next, we examine those bytes to see if they looks like a TLS
			// error message. If they do we wrap the io.ErrUnexpectedEOF
			// with some context.
			if looksLikeUnexpectedTLS(size) {
				err = fmt.Errorf("%w: broker appears to be expecting TLS", io.ErrUnexpectedEOF)
			}
			return
		}
		err = dontExpectEOF(err)
		return
	}

	res := &t.responses[apiVersion-minVersion]

	if res.flexible {
		// In the flexible case, there's a tag buffer at the end of the response header
		taggedCount := int(d.readUnsignedVarInt())
		for i := 0; i < taggedCount; i++ {
			d.readUnsignedVarInt() // tagID
			size := d.readUnsignedVarInt()

			// Just throw away the values for now
			d.read(int(size))
		}
	}

	msg = res.new()
	res.decode(d, valueOf(msg))
	d.discardAll()

	if err = d.err; err != nil {
		err = dontExpectEOF(err)
	}

	return
}

func WriteResponse(w io.Writer, apiVersion int16, correlationID int32, msg Message) error {
	apiKey := msg.ApiKey()

	if i := int(apiKey); i < 0 || i >= len(apiTypes) {
		return fmt.Errorf("unsupported api key: %d", i)
	}

	t := &apiTypes[apiKey]
	if t == nil {
		return fmt.Errorf("unsupported api: %s", apiNames[apiKey])
	}

	minVersion := t.minVersion()
	maxVersion := t.maxVersion()

	if apiVersion < minVersion || apiVersion > maxVersion {
		return fmt.Errorf("unsupported %s version: v%d not in range v%d-v%d", apiKey, apiVersion, minVersion, maxVersion)
	}

	r := &t.responses[apiVersion-minVersion]
	v := valueOf(msg)
	b := newPageBuffer()
	defer b.unref()

	e := &encoder{writer: b}
	e.writeInt32(0) // placeholder for the response size
	e.writeInt32(correlationID)
	if r.flexible {
		// Flexible messages use extra space for a tag buffer,
		// which begins with a size value. Since we're not writing any fields into the
		// latter, we can just write zero for now.
		//
		// See
		// https://cwiki.apache.org/confluence/display/KAFKA/KIP-482%3A+The+Kafka+Protocol+should+Support+Optional+Tagged+Fields
		// for details.
		e.writeUnsignedVarInt(0)
	}
	r.encode(e, v)
	err := e.err

	if err == nil {
		size := packUint32(uint32(b.Size()) - 4)
		b.WriteAt(size[:], 0)
		_, err = b.WriteTo(w)
	}

	return err
}

const (
	tlsAlertByte byte = 0x15
)

// looksLikeUnexpectedTLS returns true if the size passed in resemble
// the TLS alert message that is returned to a client which sends
// an invalid ClientHello message.
func looksLikeUnexpectedTLS(size int32) bool {
	var sizeBytes [4]byte
	binary.BigEndian.PutUint32(sizeBytes[:], uint32(size))

	if sizeBytes[0] != tlsAlertByte {
		return false
	}
	version := int(sizeBytes[1])<<8 | int(sizeBytes[2])
	return version <= tls.VersionTLS13 && version >= tls.VersionTLS10
}
