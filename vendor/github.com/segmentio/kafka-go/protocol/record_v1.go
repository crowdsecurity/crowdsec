package protocol

import (
	"errors"
	"hash/crc32"
	"io"
	"math"
	"time"
)

func readMessage(b *pageBuffer, d *decoder) (attributes int8, baseOffset, timestamp int64, key, value Bytes, err error) {
	md := decoder{
		reader: d,
		remain: 12,
	}

	baseOffset = md.readInt64()
	md.remain = int(md.readInt32())

	crc := uint32(md.readInt32())
	md.setCRC(crc32.IEEETable)
	magicByte := md.readInt8()
	attributes = md.readInt8()
	timestamp = int64(0)

	if magicByte != 0 {
		timestamp = md.readInt64()
	}

	keyOffset := b.Size()
	keyLength := int(md.readInt32())
	hasKey := keyLength >= 0
	if hasKey {
		md.writeTo(b, keyLength)
		key = b.ref(keyOffset, b.Size())
	}

	valueOffset := b.Size()
	valueLength := int(md.readInt32())
	hasValue := valueLength >= 0
	if hasValue {
		md.writeTo(b, valueLength)
		value = b.ref(valueOffset, b.Size())
	}

	if md.crc32 != crc {
		err = Errorf("crc32 checksum mismatch (computed=%d found=%d)", md.crc32, crc)
	} else {
		err = dontExpectEOF(md.err)
	}

	return
}

func (rs *RecordSet) readFromVersion1(d *decoder) error {
	var records RecordReader

	b := newPageBuffer()
	defer b.unref()

	attributes, baseOffset, timestamp, key, value, err := readMessage(b, d)
	if err != nil {
		return err
	}

	if compression := Attributes(attributes).Compression(); compression == 0 {
		records = &message{
			Record: Record{
				Offset: baseOffset,
				Time:   makeTime(timestamp),
				Key:    key,
				Value:  value,
			},
		}
	} else {
		// Can we have a non-nil key when reading a compressed message?
		if key != nil {
			key.Close()
		}
		if value == nil {
			records = emptyRecordReader{}
		} else {
			defer value.Close()

			codec := compression.Codec()
			if codec == nil {
				return Errorf("unsupported compression codec: %d", compression)
			}
			decompressor := codec.NewReader(value)
			defer decompressor.Close()

			b := newPageBuffer()
			defer b.unref()

			d := &decoder{
				reader: decompressor,
				remain: math.MaxInt32,
			}

			r := &recordReader{
				records: make([]Record, 0, 32),
			}

			for !d.done() {
				_, offset, timestamp, key, value, err := readMessage(b, d)
				if err != nil {
					if errors.Is(err, io.ErrUnexpectedEOF) {
						break
					}
					for _, rec := range r.records {
						closeBytes(rec.Key)
						closeBytes(rec.Value)
					}
					return err
				}
				r.records = append(r.records, Record{
					Offset: offset,
					Time:   makeTime(timestamp),
					Key:    key,
					Value:  value,
				})
			}

			if baseOffset != 0 {
				// https://kafka.apache.org/documentation/#messageset
				//
				// In version 1, to avoid server side re-compression, only the
				// wrapper message will be assigned an offset. The inner messages
				// will have relative offsets. The absolute offset can be computed
				// using the offset from the outer message, which corresponds to the
				// offset assigned to the last inner message.
				lastRelativeOffset := int64(len(r.records)) - 1

				for i := range r.records {
					r.records[i].Offset = baseOffset - (lastRelativeOffset - r.records[i].Offset)
				}
			}

			records = r
		}
	}

	*rs = RecordSet{
		Version:    1,
		Attributes: Attributes(attributes),
		Records:    records,
	}

	return nil
}

func (rs *RecordSet) writeToVersion1(buffer *pageBuffer, bufferOffset int64) error {
	attributes := rs.Attributes
	records := rs.Records

	if compression := attributes.Compression(); compression != 0 {
		if codec := compression.Codec(); codec != nil {
			// In the message format version 1, compression is achieved by
			// compressing the value of a message which recursively contains
			// the representation of the compressed message set.
			subset := *rs
			subset.Attributes &= ^7 // erase compression

			if err := subset.writeToVersion1(buffer, bufferOffset); err != nil {
				return err
			}

			compressed := newPageBuffer()
			defer compressed.unref()

			compressor := codec.NewWriter(compressed)
			defer compressor.Close()

			var err error
			buffer.pages.scan(bufferOffset, buffer.Size(), func(b []byte) bool {
				_, err = compressor.Write(b)
				return err == nil
			})
			if err != nil {
				return err
			}
			if err := compressor.Close(); err != nil {
				return err
			}

			buffer.Truncate(int(bufferOffset))

			records = &message{
				Record: Record{
					Value: compressed,
				},
			}
		}
	}

	e := encoder{writer: buffer}
	currentTimestamp := timestamp(time.Now())

	return forEachRecord(records, func(i int, r *Record) error {
		t := timestamp(r.Time)
		if t == 0 {
			t = currentTimestamp
		}

		messageOffset := buffer.Size()
		e.writeInt64(int64(i))
		e.writeInt32(0) // message size placeholder
		e.writeInt32(0) // crc32 placeholder
		e.setCRC(crc32.IEEETable)
		e.writeInt8(1) // magic byte: version 1
		e.writeInt8(int8(attributes))
		e.writeInt64(t)

		if err := e.writeNullBytesFrom(r.Key); err != nil {
			return err
		}

		if err := e.writeNullBytesFrom(r.Value); err != nil {
			return err
		}

		b0 := packUint32(uint32(buffer.Size() - (messageOffset + 12)))
		b1 := packUint32(e.crc32)

		buffer.WriteAt(b0[:], messageOffset+8)
		buffer.WriteAt(b1[:], messageOffset+12)
		e.setCRC(nil)
		return nil
	})
}

type message struct {
	Record Record
	read   bool
}

func (m *message) ReadRecord() (*Record, error) {
	if m.read {
		return nil, io.EOF
	}
	m.read = true
	return &m.Record, nil
}
