package kafka

import (
	"time"
)

// Message is a data structure representing kafka messages.
type Message struct {
	// Topic indicates which topic this message was consumed from via Reader.
	//
	// When being used with Writer, this can be used to configure the topic if
	// not already specified on the writer itself.
	Topic string

	// Partition is read-only and MUST NOT be set when writing messages
	Partition     int
	Offset        int64
	HighWaterMark int64
	Key           []byte
	Value         []byte
	Headers       []Header

	// If not set at the creation, Time will be automatically set when
	// writing the message.
	Time time.Time
}

func (msg Message) message(cw *crc32Writer) message {
	m := message{
		MagicByte: 1,
		Key:       msg.Key,
		Value:     msg.Value,
		Timestamp: timestamp(msg.Time),
	}
	if cw != nil {
		m.CRC = m.crc32(cw)
	}
	return m
}

const timestampSize = 8

func (msg *Message) size() int32 {
	return 4 + 1 + 1 + sizeofBytes(msg.Key) + sizeofBytes(msg.Value) + timestampSize
}

type message struct {
	CRC        int32
	MagicByte  int8
	Attributes int8
	Timestamp  int64
	Key        []byte
	Value      []byte
}

func (m message) crc32(cw *crc32Writer) int32 {
	cw.crc32 = 0
	cw.writeInt8(m.MagicByte)
	cw.writeInt8(m.Attributes)
	if m.MagicByte != 0 {
		cw.writeInt64(m.Timestamp)
	}
	cw.writeBytes(m.Key)
	cw.writeBytes(m.Value)
	return int32(cw.crc32)
}

func (m message) size() int32 {
	size := 4 + 1 + 1 + sizeofBytes(m.Key) + sizeofBytes(m.Value)
	if m.MagicByte != 0 {
		size += timestampSize
	}
	return size
}

func (m message) writeTo(wb *writeBuffer) {
	wb.writeInt32(m.CRC)
	wb.writeInt8(m.MagicByte)
	wb.writeInt8(m.Attributes)
	if m.MagicByte != 0 {
		wb.writeInt64(m.Timestamp)
	}
	wb.writeBytes(m.Key)
	wb.writeBytes(m.Value)
}

type messageSetItem struct {
	Offset      int64
	MessageSize int32
	Message     message
}

func (m messageSetItem) size() int32 {
	return 8 + 4 + m.Message.size()
}

func (m messageSetItem) writeTo(wb *writeBuffer) {
	wb.writeInt64(m.Offset)
	wb.writeInt32(m.MessageSize)
	m.Message.writeTo(wb)
}

type messageSet []messageSetItem

func (s messageSet) size() (size int32) {
	for _, m := range s {
		size += m.size()
	}
	return
}

func (s messageSet) writeTo(wb *writeBuffer) {
	for _, m := range s {
		m.writeTo(wb)
	}
}
