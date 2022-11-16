package kafka

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
)

type readBytesFunc func(*bufio.Reader, int, int) (int, error)

// messageSetReader processes the messages encoded into a fetch response.
// The response may contain a mix of Record Batches (newer format) and Messages
// (older format).
type messageSetReader struct {
	*readerStack      // used for decompressing compressed messages and record batches
	empty        bool // if true, short circuits messageSetReader methods
	debug        bool // enable debug log messages
	// How many bytes are expected to remain in the response.
	//
	// This is used to detect truncation of the response.
	lengthRemain int

	decompressed bytes.Buffer
}

type readerStack struct {
	reader *bufio.Reader
	remain int
	base   int64
	parent *readerStack
	count  int            // how many messages left in the current message set
	header messagesHeader // the current header for a subset of messages within the set.
}

// messagesHeader describes a set of records. there may be many messagesHeader's in a message set.
type messagesHeader struct {
	firstOffset int64
	length      int32
	crc         int32
	magic       int8
	// v1 composes attributes specific to v0 and v1 message headers
	v1 struct {
		attributes int8
		timestamp  int64
	}
	// v2 composes attributes specific to v2 message headers
	v2 struct {
		leaderEpoch     int32
		attributes      int16
		lastOffsetDelta int32
		firstTimestamp  int64
		lastTimestamp   int64
		producerID      int64
		producerEpoch   int16
		baseSequence    int32
		count           int32
	}
}

func (h messagesHeader) compression() (codec CompressionCodec, err error) {
	const compressionCodecMask = 0x07
	var code int8
	switch h.magic {
	case 0, 1:
		code = h.v1.attributes & compressionCodecMask
	case 2:
		code = int8(h.v2.attributes & compressionCodecMask)
	default:
		err = h.badMagic()
		return
	}
	if code != 0 {
		codec, err = resolveCodec(code)
	}
	return
}

func (h messagesHeader) badMagic() error {
	return fmt.Errorf("unsupported magic byte %d in header", h.magic)
}

func newMessageSetReader(reader *bufio.Reader, remain int) (*messageSetReader, error) {
	res := &messageSetReader{
		readerStack: &readerStack{
			reader: reader,
			remain: remain,
		},
	}
	err := res.readHeader()
	return res, err
}

func (r *messageSetReader) remaining() (remain int) {
	if r.empty {
		return 0
	}
	for s := r.readerStack; s != nil; s = s.parent {
		remain += s.remain
	}
	return
}

func (r *messageSetReader) discard() (err error) {
	switch {
	case r.empty:
	case r.readerStack == nil:
	default:
		// rewind up to the top-most reader b/c it's the only one that's doing
		// actual i/o.  the rest are byte buffers that have been pushed on the stack
		// while reading compressed message sets.
		for r.parent != nil {
			r.readerStack = r.parent
		}
		err = r.discardN(r.remain)
	}
	return
}

func (r *messageSetReader) readMessage(min int64, key readBytesFunc, val readBytesFunc) (
	offset int64, lastOffset int64, timestamp int64, headers []Header, err error) {

	if r.empty {
		err = RequestTimedOut
		return
	}
	if err = r.readHeader(); err != nil {
		return
	}
	switch r.header.magic {
	case 0, 1:
		offset, timestamp, headers, err = r.readMessageV1(min, key, val)
		// Set an invalid value so that it can be ignored
		lastOffset = -1
	case 2:
		offset, lastOffset, timestamp, headers, err = r.readMessageV2(min, key, val)
	default:
		err = r.header.badMagic()
	}
	return
}

func (r *messageSetReader) readMessageV1(min int64, key readBytesFunc, val readBytesFunc) (
	offset int64, timestamp int64, headers []Header, err error) {

	for r.readerStack != nil {
		if r.remain == 0 {
			r.readerStack = r.parent
			continue
		}
		if err = r.readHeader(); err != nil {
			return
		}
		offset = r.header.firstOffset
		timestamp = r.header.v1.timestamp
		var codec CompressionCodec
		if codec, err = r.header.compression(); err != nil {
			return
		}
		r.log("Reading with codec=%T", codec)
		if codec != nil {
			// discard next four bytes...will be -1 to indicate null key
			if err = r.discardN(4); err != nil {
				return
			}

			// read and decompress the contained message set.
			r.decompressed.Reset()
			if err = r.readBytesWith(func(br *bufio.Reader, sz int, n int) (remain int, err error) {
				// x4 as a guess that the average compression ratio is near 75%
				r.decompressed.Grow(4 * n)
				limitReader := io.LimitedReader{R: br, N: int64(n)}
				codecReader := codec.NewReader(&limitReader)
				_, err = r.decompressed.ReadFrom(codecReader)
				remain = sz - (n - int(limitReader.N))
				codecReader.Close()
				return
			}); err != nil {
				return
			}

			// the compressed message's offset will be equal to the offset of
			// the last message in the set.  within the compressed set, the
			// offsets will be relative, so we have to scan through them to
			// get the base offset.  for example, if there are four compressed
			// messages at offsets 10-13, then the container message will have
			// offset 13 and the contained messages will be 0,1,2,3.  the base
			// offset for the container, then is 13-3=10.
			if offset, err = extractOffset(offset, r.decompressed.Bytes()); err != nil {
				return
			}

			// mark the outer message as being read
			r.markRead()

			// then push the decompressed bytes onto the stack.
			r.readerStack = &readerStack{
				// Allocate a buffer of size 0, which gets capped at 16 bytes
				// by the bufio package. We are already reading buffered data
				// here, no need to reserve another 4KB buffer.
				reader: bufio.NewReaderSize(&r.decompressed, 0),
				remain: r.decompressed.Len(),
				base:   offset,
				parent: r.readerStack,
			}
			continue
		}

		// adjust the offset in case we're reading compressed messages.  the
		// base will be zero otherwise.
		offset += r.base

		// When the messages are compressed kafka may return messages at an
		// earlier offset than the one that was requested, it's the client's
		// responsibility to ignore those.
		//
		// At this point, the message header has been read, so discarding
		// the rest of the message means we have to discard the key, and then
		// the value. Each of those are preceded by a 4-byte length. Discarding
		// them is then reading that length variable and then discarding that
		// amount.
		if offset < min {
			// discard the key
			if err = r.discardBytes(); err != nil {
				return
			}
			// discard the value
			if err = r.discardBytes(); err != nil {
				return
			}
			// since we have fully consumed the message, mark as read
			r.markRead()
			continue
		}
		if err = r.readBytesWith(key); err != nil {
			return
		}
		if err = r.readBytesWith(val); err != nil {
			return
		}
		r.markRead()
		return
	}
	err = errShortRead
	return
}

func (r *messageSetReader) readMessageV2(_ int64, key readBytesFunc, val readBytesFunc) (
	offset int64, lastOffset int64, timestamp int64, headers []Header, err error) {
	if err = r.readHeader(); err != nil {
		return
	}
	if r.count == int(r.header.v2.count) { // first time reading this set, so check for compression headers.
		var codec CompressionCodec
		if codec, err = r.header.compression(); err != nil {
			return
		}
		if codec != nil {
			batchRemain := int(r.header.length - 49) // TODO: document this magic number
			if batchRemain > r.remain {
				err = errShortRead
				return
			}
			if batchRemain < 0 {
				err = fmt.Errorf("batch remain < 0 (%d)", batchRemain)
				return
			}
			r.decompressed.Reset()
			// x4 as a guess that the average compression ratio is near 75%
			r.decompressed.Grow(4 * batchRemain)
			limitReader := io.LimitedReader{R: r.reader, N: int64(batchRemain)}
			codecReader := codec.NewReader(&limitReader)
			_, err = r.decompressed.ReadFrom(codecReader)
			codecReader.Close()
			if err != nil {
				return
			}
			r.remain -= batchRemain - int(limitReader.N)
			r.readerStack = &readerStack{
				reader: bufio.NewReaderSize(&r.decompressed, 0), // the new stack reads from the decompressed buffer
				remain: r.decompressed.Len(),
				base:   -1, // base is unused here
				parent: r.readerStack,
				header: r.header,
				count:  r.count,
			}
			// all of the messages in this set are in the decompressed set just pushed onto the reader
			// stack. here we set the parent count to 0 so that when the child set is exhausted, the
			// reader will then try to read the header of the next message set
			r.readerStack.parent.count = 0
		}
	}
	remainBefore := r.remain
	var length int64
	if err = r.readVarInt(&length); err != nil {
		return
	}
	lengthOfLength := remainBefore - r.remain
	var attrs int8
	if err = r.readInt8(&attrs); err != nil {
		return
	}
	var timestampDelta int64
	if err = r.readVarInt(&timestampDelta); err != nil {
		return
	}
	timestamp = r.header.v2.firstTimestamp + timestampDelta
	var offsetDelta int64
	if err = r.readVarInt(&offsetDelta); err != nil {
		return
	}
	offset = r.header.firstOffset + offsetDelta
	if err = r.runFunc(key); err != nil {
		return
	}
	if err = r.runFunc(val); err != nil {
		return
	}
	var headerCount int64
	if err = r.readVarInt(&headerCount); err != nil {
		return
	}
	if headerCount > 0 {
		headers = make([]Header, headerCount)
		for i := range headers {
			if err = r.readMessageHeader(&headers[i]); err != nil {
				return
			}
		}
	}
	lastOffset = r.header.firstOffset + int64(r.header.v2.lastOffsetDelta)
	r.lengthRemain -= int(length) + lengthOfLength
	r.markRead()
	return
}

func (r *messageSetReader) discardBytes() (err error) {
	r.remain, err = discardBytes(r.reader, r.remain)
	return
}

func (r *messageSetReader) discardN(sz int) (err error) {
	r.remain, err = discardN(r.reader, r.remain, sz)
	return
}

func (r *messageSetReader) markRead() {
	if r.count == 0 {
		panic("markRead: negative count")
	}
	r.count--
	r.unwindStack()
	r.log("Mark read remain=%d", r.remain)
}

func (r *messageSetReader) unwindStack() {
	for r.count == 0 {
		if r.remain == 0 {
			if r.parent != nil {
				r.log("Popped reader stack")
				r.readerStack = r.parent
				continue
			}
		}
		break
	}
}

func (r *messageSetReader) readMessageHeader(header *Header) (err error) {
	var keyLen int64
	if err = r.readVarInt(&keyLen); err != nil {
		return
	}
	if header.Key, err = r.readNewString(int(keyLen)); err != nil {
		return
	}
	var valLen int64
	if err = r.readVarInt(&valLen); err != nil {
		return
	}
	if header.Value, err = r.readNewBytes(int(valLen)); err != nil {
		return
	}
	return nil
}

func (r *messageSetReader) runFunc(rbFunc readBytesFunc) (err error) {
	var length int64
	if err = r.readVarInt(&length); err != nil {
		return
	}
	if r.remain, err = rbFunc(r.reader, r.remain, int(length)); err != nil {
		return
	}
	return
}

func (r *messageSetReader) readHeader() (err error) {
	if r.count > 0 {
		// currently reading a set of messages, no need to read a header until they are exhausted.
		return
	}
	r.header = messagesHeader{}
	if err = r.readInt64(&r.header.firstOffset); err != nil {
		return
	}
	if err = r.readInt32(&r.header.length); err != nil {
		return
	}
	var crcOrLeaderEpoch int32
	if err = r.readInt32(&crcOrLeaderEpoch); err != nil {
		return
	}
	if err = r.readInt8(&r.header.magic); err != nil {
		return
	}
	switch r.header.magic {
	case 0:
		r.header.crc = crcOrLeaderEpoch
		if err = r.readInt8(&r.header.v1.attributes); err != nil {
			return
		}
		r.count = 1
		// Set arbitrary non-zero length so that we always assume the
		// message is truncated since bytes remain.
		r.lengthRemain = 1
		r.log("Read v0 header with offset=%d len=%d magic=%d attributes=%d", r.header.firstOffset, r.header.length, r.header.magic, r.header.v1.attributes)
	case 1:
		r.header.crc = crcOrLeaderEpoch
		if err = r.readInt8(&r.header.v1.attributes); err != nil {
			return
		}
		if err = r.readInt64(&r.header.v1.timestamp); err != nil {
			return
		}
		r.count = 1
		// Set arbitrary non-zero length so that we always assume the
		// message is truncated since bytes remain.
		r.lengthRemain = 1
		r.log("Read v1 header with remain=%d offset=%d magic=%d and attributes=%d", r.remain, r.header.firstOffset, r.header.magic, r.header.v1.attributes)
	case 2:
		r.header.v2.leaderEpoch = crcOrLeaderEpoch
		if err = r.readInt32(&r.header.crc); err != nil {
			return
		}
		if err = r.readInt16(&r.header.v2.attributes); err != nil {
			return
		}
		if err = r.readInt32(&r.header.v2.lastOffsetDelta); err != nil {
			return
		}
		if err = r.readInt64(&r.header.v2.firstTimestamp); err != nil {
			return
		}
		if err = r.readInt64(&r.header.v2.lastTimestamp); err != nil {
			return
		}
		if err = r.readInt64(&r.header.v2.producerID); err != nil {
			return
		}
		if err = r.readInt16(&r.header.v2.producerEpoch); err != nil {
			return
		}
		if err = r.readInt32(&r.header.v2.baseSequence); err != nil {
			return
		}
		if err = r.readInt32(&r.header.v2.count); err != nil {
			return
		}
		r.count = int(r.header.v2.count)
		// Subtracts the header bytes from the length
		r.lengthRemain = int(r.header.length) - 49
		r.log("Read v2 header with count=%d offset=%d len=%d magic=%d attributes=%d", r.count, r.header.firstOffset, r.header.length, r.header.magic, r.header.v2.attributes)
	default:
		err = r.header.badMagic()
		return
	}
	return
}

func (r *messageSetReader) readNewBytes(len int) (res []byte, err error) {
	res, r.remain, err = readNewBytes(r.reader, r.remain, len)
	return
}

func (r *messageSetReader) readNewString(len int) (res string, err error) {
	res, r.remain, err = readNewString(r.reader, r.remain, len)
	return
}

func (r *messageSetReader) readInt8(val *int8) (err error) {
	r.remain, err = readInt8(r.reader, r.remain, val)
	return
}

func (r *messageSetReader) readInt16(val *int16) (err error) {
	r.remain, err = readInt16(r.reader, r.remain, val)
	return
}

func (r *messageSetReader) readInt32(val *int32) (err error) {
	r.remain, err = readInt32(r.reader, r.remain, val)
	return
}

func (r *messageSetReader) readInt64(val *int64) (err error) {
	r.remain, err = readInt64(r.reader, r.remain, val)
	return
}

func (r *messageSetReader) readVarInt(val *int64) (err error) {
	r.remain, err = readVarInt(r.reader, r.remain, val)
	return
}

func (r *messageSetReader) readBytesWith(fn readBytesFunc) (err error) {
	r.remain, err = readBytesWith(r.reader, r.remain, fn)
	return
}

func (r *messageSetReader) log(msg string, args ...interface{}) {
	if r.debug {
		log.Printf("[DEBUG] "+msg, args...)
	}
}

func extractOffset(base int64, msgSet []byte) (offset int64, err error) {
	r, remain := bufio.NewReader(bytes.NewReader(msgSet)), len(msgSet)
	for remain > 0 {
		if remain, err = readInt64(r, remain, &offset); err != nil {
			return
		}
		var sz int32
		if remain, err = readInt32(r, remain, &sz); err != nil {
			return
		}
		if remain, err = discardN(r, remain, int(sz)); err != nil {
			return
		}
	}
	offset = base - offset
	return
}
