package protocol

import (
	"fmt"
	"hash/crc32"
	"io"
	"time"
)

func (rs *RecordSet) readFromVersion2(d *decoder) error {
	baseOffset := d.readInt64()
	batchLength := d.readInt32()

	if int(batchLength) > d.remain || d.err != nil {
		d.discardAll()
		return nil
	}

	dec := &decoder{
		reader: d,
		remain: int(batchLength),
	}

	partitionLeaderEpoch := dec.readInt32()
	magicByte := dec.readInt8()
	crc := dec.readInt32()

	dec.setCRC(crc32.MakeTable(crc32.Castagnoli))

	attributes := dec.readInt16()
	lastOffsetDelta := dec.readInt32()
	firstTimestamp := dec.readInt64()
	maxTimestamp := dec.readInt64()
	producerID := dec.readInt64()
	producerEpoch := dec.readInt16()
	baseSequence := dec.readInt32()
	numRecords := dec.readInt32()
	reader := io.Reader(dec)

	// unused
	_ = lastOffsetDelta
	_ = maxTimestamp

	if compression := Attributes(attributes).Compression(); compression != 0 {
		codec := compression.Codec()
		if codec == nil {
			return fmt.Errorf("unsupported compression codec (%d)", compression)
		}
		decompressor := codec.NewReader(reader)
		defer decompressor.Close()
		reader = decompressor
	}

	buffer := newPageBuffer()
	defer buffer.unref()

	_, err := buffer.ReadFrom(reader)
	if err != nil {
		return err
	}
	if dec.crc32 != uint32(crc) {
		return fmt.Errorf("crc32 checksum mismatch (computed=%d found=%d)", dec.crc32, uint32(crc))
	}

	recordsLength := buffer.Len()
	dec.reader = buffer
	dec.remain = recordsLength

	records := make([]optimizedRecord, numRecords)
	// These are two lazy allocators that will be used to optimize allocation of
	// page references for keys and values.
	//
	// By default, no memory is allocated and on first use, numRecords page refs
	// are allocated in a contiguous memory space, and the allocators return
	// pointers into those arrays for each page ref that get requested.
	//
	// The reasoning is that kafka partitions typically have records of a single
	// form, which either have no keys, no values, or both keys and values.
	// Using lazy allocators adapts nicely to these patterns to only allocate
	// the memory that is needed by the program, while still reducing the number
	// of malloc calls made by the program.
	//
	// Using a single allocator for both keys and values keeps related values
	// close by in memory, making access to the records more friendly to CPU
	// caches.
	alloc := pageRefAllocator{size: int(numRecords)}
	// Following the same reasoning that kafka partitions will typically have
	// records with repeating formats, we expect to either find records with
	// no headers, or records which always contain headers.
	//
	// To reduce the memory footprint when records have no headers, the Header
	// slices are lazily allocated in a separate array.
	headers := ([][]Header)(nil)

	for i := range records {
		r := &records[i]
		_ = dec.readVarInt() // record length (unused)
		_ = dec.readInt8()   // record attributes (unused)
		timestampDelta := dec.readVarInt()
		offsetDelta := dec.readVarInt()

		r.offset = baseOffset + offsetDelta
		r.timestamp = firstTimestamp + timestampDelta

		keyLength := dec.readVarInt()
		keyOffset := int64(recordsLength - dec.remain)
		if keyLength > 0 {
			dec.discard(int(keyLength))
		}

		valueLength := dec.readVarInt()
		valueOffset := int64(recordsLength - dec.remain)
		if valueLength > 0 {
			dec.discard(int(valueLength))
		}

		if numHeaders := dec.readVarInt(); numHeaders > 0 {
			if headers == nil {
				headers = make([][]Header, numRecords)
			}

			h := make([]Header, numHeaders)

			for i := range h {
				h[i] = Header{
					Key:   dec.readVarString(),
					Value: dec.readVarBytes(),
				}
			}

			headers[i] = h
		}

		if dec.err != nil {
			records = records[:i]
			break
		}

		if keyLength >= 0 {
			r.keyRef = alloc.newPageRef()
			buffer.refTo(r.keyRef, keyOffset, keyOffset+keyLength)
		}

		if valueLength >= 0 {
			r.valueRef = alloc.newPageRef()
			buffer.refTo(r.valueRef, valueOffset, valueOffset+valueLength)
		}
	}

	// Note: it's unclear whether kafka 0.11+ still truncates the responses,
	// all attempts I made at constructing a test to trigger a truncation have
	// failed. I kept this code here as a safeguard but it may never execute.
	if dec.err != nil && len(records) == 0 {
		return dec.err
	}

	*rs = RecordSet{
		Version:    magicByte,
		Attributes: Attributes(attributes),
		Records: &optimizedRecordReader{
			records: records,
			headers: headers,
		},
	}

	if rs.Attributes.Control() {
		rs.Records = &ControlBatch{
			Attributes:           rs.Attributes,
			PartitionLeaderEpoch: partitionLeaderEpoch,
			BaseOffset:           baseOffset,
			ProducerID:           producerID,
			ProducerEpoch:        producerEpoch,
			BaseSequence:         baseSequence,
			Records:              rs.Records,
		}
	} else {
		rs.Records = &RecordBatch{
			Attributes:           rs.Attributes,
			PartitionLeaderEpoch: partitionLeaderEpoch,
			BaseOffset:           baseOffset,
			ProducerID:           producerID,
			ProducerEpoch:        producerEpoch,
			BaseSequence:         baseSequence,
			Records:              rs.Records,
		}
	}

	return nil
}

func (rs *RecordSet) writeToVersion2(buffer *pageBuffer, bufferOffset int64) error {
	records := rs.Records
	numRecords := int32(0)

	e := &encoder{writer: buffer}
	e.writeInt64(0)                    // base offset                         |  0 +8
	e.writeInt32(0)                    // placeholder for record batch length |  8 +4
	e.writeInt32(-1)                   // partition leader epoch              | 12 +3
	e.writeInt8(2)                     // magic byte                          | 16 +1
	e.writeInt32(0)                    // placeholder for crc32 checksum      | 17 +4
	e.writeInt16(int16(rs.Attributes)) // attributes                          | 21 +2
	e.writeInt32(0)                    // placeholder for lastOffsetDelta     | 23 +4
	e.writeInt64(0)                    // placeholder for firstTimestamp      | 27 +8
	e.writeInt64(0)                    // placeholder for maxTimestamp        | 35 +8
	e.writeInt64(-1)                   // producer id                         | 43 +8
	e.writeInt16(-1)                   // producer epoch                      | 51 +2
	e.writeInt32(-1)                   // base sequence                       | 53 +4
	e.writeInt32(0)                    // placeholder for numRecords          | 57 +4

	var compressor io.WriteCloser
	if compression := rs.Attributes.Compression(); compression != 0 {
		if codec := compression.Codec(); codec != nil {
			compressor = codec.NewWriter(buffer)
			e.writer = compressor
		}
	}

	currentTimestamp := timestamp(time.Now())
	lastOffsetDelta := int32(0)
	firstTimestamp := int64(0)
	maxTimestamp := int64(0)

	err := forEachRecord(records, func(i int, r *Record) error {
		t := timestamp(r.Time)
		if t == 0 {
			t = currentTimestamp
		}
		if i == 0 {
			firstTimestamp = t
		}
		if t > maxTimestamp {
			maxTimestamp = t
		}

		timestampDelta := t - firstTimestamp
		offsetDelta := int64(i)
		lastOffsetDelta = int32(offsetDelta)

		length := 1 + // attributes
			sizeOfVarInt(timestampDelta) +
			sizeOfVarInt(offsetDelta) +
			sizeOfVarNullBytesIface(r.Key) +
			sizeOfVarNullBytesIface(r.Value) +
			sizeOfVarInt(int64(len(r.Headers)))

		for _, h := range r.Headers {
			length += sizeOfVarString(h.Key) + sizeOfVarNullBytes(h.Value)
		}

		e.writeVarInt(int64(length))
		e.writeInt8(0) // record attributes (unused)
		e.writeVarInt(timestampDelta)
		e.writeVarInt(offsetDelta)

		if err := e.writeVarNullBytesFrom(r.Key); err != nil {
			return err
		}

		if err := e.writeVarNullBytesFrom(r.Value); err != nil {
			return err
		}

		e.writeVarInt(int64(len(r.Headers)))

		for _, h := range r.Headers {
			e.writeVarString(h.Key)
			e.writeVarNullBytes(h.Value)
		}

		numRecords++
		return nil
	})

	if err != nil {
		return err
	}

	if compressor != nil {
		if err := compressor.Close(); err != nil {
			return err
		}
	}

	if numRecords == 0 {
		return ErrNoRecord
	}

	b2 := packUint32(uint32(lastOffsetDelta))
	b3 := packUint64(uint64(firstTimestamp))
	b4 := packUint64(uint64(maxTimestamp))
	b5 := packUint32(uint32(numRecords))

	buffer.WriteAt(b2[:], bufferOffset+23)
	buffer.WriteAt(b3[:], bufferOffset+27)
	buffer.WriteAt(b4[:], bufferOffset+35)
	buffer.WriteAt(b5[:], bufferOffset+57)

	totalLength := buffer.Size() - bufferOffset
	batchLength := totalLength - 12

	checksum := uint32(0)
	crcTable := crc32.MakeTable(crc32.Castagnoli)

	buffer.pages.scan(bufferOffset+21, bufferOffset+totalLength, func(chunk []byte) bool {
		checksum = crc32.Update(checksum, crcTable, chunk)
		return true
	})

	b0 := packUint32(uint32(batchLength))
	b1 := packUint32(checksum)

	buffer.WriteAt(b0[:], bufferOffset+8)
	buffer.WriteAt(b1[:], bufferOffset+17)
	return nil
}
