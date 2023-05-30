package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
)

type encoder struct {
	writer io.Writer
	err    error
	table  *crc32.Table
	crc32  uint32
	buffer [32]byte
}

type encoderChecksum struct {
	reader  io.Reader
	encoder *encoder
}

func (e *encoderChecksum) Read(b []byte) (int, error) {
	n, err := e.reader.Read(b)
	if n > 0 {
		e.encoder.update(b[:n])
	}
	return n, err
}

func (e *encoder) Reset(w io.Writer) {
	e.writer = w
	e.err = nil
	e.table = nil
	e.crc32 = 0
	e.buffer = [32]byte{}
}

func (e *encoder) ReadFrom(r io.Reader) (int64, error) {
	if e.table != nil {
		r = &encoderChecksum{
			reader:  r,
			encoder: e,
		}
	}
	return io.Copy(e.writer, r)
}

func (e *encoder) Write(b []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.writer.Write(b)
	if n > 0 {
		e.update(b[:n])
	}
	if err != nil {
		e.err = err
	}
	return n, err
}

func (e *encoder) WriteByte(b byte) error {
	e.buffer[0] = b
	_, err := e.Write(e.buffer[:1])
	return err
}

func (e *encoder) WriteString(s string) (int, error) {
	// This implementation is an optimization to avoid the heap allocation that
	// would occur when converting the string to a []byte to call crc32.Update.
	//
	// Strings are rarely long in the kafka protocol, so the use of a 32 byte
	// buffer is a good comprise between keeping the encoder value small and
	// limiting the number of calls to Write.
	//
	// We introduced this optimization because memory profiles on the benchmarks
	// showed that most heap allocations were caused by this code path.
	n := 0

	for len(s) != 0 {
		c := copy(e.buffer[:], s)
		w, err := e.Write(e.buffer[:c])
		n += w
		if err != nil {
			return n, err
		}
		s = s[c:]
	}

	return n, nil
}

func (e *encoder) setCRC(table *crc32.Table) {
	e.table, e.crc32 = table, 0
}

func (e *encoder) update(b []byte) {
	if e.table != nil {
		e.crc32 = crc32.Update(e.crc32, e.table, b)
	}
}

func (e *encoder) encodeBool(v value) {
	b := int8(0)
	if v.bool() {
		b = 1
	}
	e.writeInt8(b)
}

func (e *encoder) encodeInt8(v value) {
	e.writeInt8(v.int8())
}

func (e *encoder) encodeInt16(v value) {
	e.writeInt16(v.int16())
}

func (e *encoder) encodeInt32(v value) {
	e.writeInt32(v.int32())
}

func (e *encoder) encodeInt64(v value) {
	e.writeInt64(v.int64())
}

func (e *encoder) encodeString(v value) {
	e.writeString(v.string())
}

func (e *encoder) encodeCompactString(v value) {
	e.writeCompactString(v.string())
}

func (e *encoder) encodeNullString(v value) {
	e.writeNullString(v.string())
}

func (e *encoder) encodeCompactNullString(v value) {
	e.writeCompactNullString(v.string())
}

func (e *encoder) encodeBytes(v value) {
	e.writeBytes(v.bytes())
}

func (e *encoder) encodeCompactBytes(v value) {
	e.writeCompactBytes(v.bytes())
}

func (e *encoder) encodeNullBytes(v value) {
	e.writeNullBytes(v.bytes())
}

func (e *encoder) encodeCompactNullBytes(v value) {
	e.writeCompactNullBytes(v.bytes())
}

func (e *encoder) encodeArray(v value, elemType reflect.Type, encodeElem encodeFunc) {
	a := v.array(elemType)
	n := a.length()
	e.writeInt32(int32(n))

	for i := 0; i < n; i++ {
		encodeElem(e, a.index(i))
	}
}

func (e *encoder) encodeCompactArray(v value, elemType reflect.Type, encodeElem encodeFunc) {
	a := v.array(elemType)
	n := a.length()
	e.writeUnsignedVarInt(uint64(n + 1))

	for i := 0; i < n; i++ {
		encodeElem(e, a.index(i))
	}
}

func (e *encoder) encodeNullArray(v value, elemType reflect.Type, encodeElem encodeFunc) {
	a := v.array(elemType)
	if a.isNil() {
		e.writeInt32(-1)
		return
	}

	n := a.length()
	e.writeInt32(int32(n))

	for i := 0; i < n; i++ {
		encodeElem(e, a.index(i))
	}
}

func (e *encoder) encodeCompactNullArray(v value, elemType reflect.Type, encodeElem encodeFunc) {
	a := v.array(elemType)
	if a.isNil() {
		e.writeUnsignedVarInt(0)
		return
	}

	n := a.length()
	e.writeUnsignedVarInt(uint64(n + 1))
	for i := 0; i < n; i++ {
		encodeElem(e, a.index(i))
	}
}

func (e *encoder) writeInt8(i int8) {
	writeInt8(e.buffer[:1], i)
	e.Write(e.buffer[:1])
}

func (e *encoder) writeInt16(i int16) {
	writeInt16(e.buffer[:2], i)
	e.Write(e.buffer[:2])
}

func (e *encoder) writeInt32(i int32) {
	writeInt32(e.buffer[:4], i)
	e.Write(e.buffer[:4])
}

func (e *encoder) writeInt64(i int64) {
	writeInt64(e.buffer[:8], i)
	e.Write(e.buffer[:8])
}

func (e *encoder) writeString(s string) {
	e.writeInt16(int16(len(s)))
	e.WriteString(s)
}

func (e *encoder) writeVarString(s string) {
	e.writeVarInt(int64(len(s)))
	e.WriteString(s)
}

func (e *encoder) writeCompactString(s string) {
	e.writeUnsignedVarInt(uint64(len(s)) + 1)
	e.WriteString(s)
}

func (e *encoder) writeNullString(s string) {
	if s == "" {
		e.writeInt16(-1)
	} else {
		e.writeInt16(int16(len(s)))
		e.WriteString(s)
	}
}

func (e *encoder) writeCompactNullString(s string) {
	if s == "" {
		e.writeUnsignedVarInt(0)
	} else {
		e.writeUnsignedVarInt(uint64(len(s)) + 1)
		e.WriteString(s)
	}
}

func (e *encoder) writeBytes(b []byte) {
	e.writeInt32(int32(len(b)))
	e.Write(b)
}

func (e *encoder) writeCompactBytes(b []byte) {
	e.writeUnsignedVarInt(uint64(len(b)) + 1)
	e.Write(b)
}

func (e *encoder) writeNullBytes(b []byte) {
	if b == nil {
		e.writeInt32(-1)
	} else {
		e.writeInt32(int32(len(b)))
		e.Write(b)
	}
}

func (e *encoder) writeVarNullBytes(b []byte) {
	if b == nil {
		e.writeVarInt(-1)
	} else {
		e.writeVarInt(int64(len(b)))
		e.Write(b)
	}
}

func (e *encoder) writeCompactNullBytes(b []byte) {
	if b == nil {
		e.writeUnsignedVarInt(0)
	} else {
		e.writeUnsignedVarInt(uint64(len(b)) + 1)
		e.Write(b)
	}
}

func (e *encoder) writeNullBytesFrom(b Bytes) error {
	if b == nil {
		e.writeInt32(-1)
		return nil
	} else {
		size := int64(b.Len())
		e.writeInt32(int32(size))
		n, err := io.Copy(e, b)
		if err == nil && n != size {
			err = fmt.Errorf("size of nullable bytes does not match the number of bytes that were written (size=%d, written=%d): %w", size, n, io.ErrUnexpectedEOF)
		}
		return err
	}
}

func (e *encoder) writeVarNullBytesFrom(b Bytes) error {
	if b == nil {
		e.writeVarInt(-1)
		return nil
	} else {
		size := int64(b.Len())
		e.writeVarInt(size)
		n, err := io.Copy(e, b)
		if err == nil && n != size {
			err = fmt.Errorf("size of nullable bytes does not match the number of bytes that were written (size=%d, written=%d): %w", size, n, io.ErrUnexpectedEOF)
		}
		return err
	}
}

func (e *encoder) writeVarInt(i int64) {
	e.writeUnsignedVarInt(uint64((i << 1) ^ (i >> 63)))
}

func (e *encoder) writeUnsignedVarInt(i uint64) {
	b := e.buffer[:]
	n := 0

	for i >= 0x80 && n < len(b) {
		b[n] = byte(i) | 0x80
		i >>= 7
		n++
	}

	if n < len(b) {
		b[n] = byte(i)
		n++
	}

	e.Write(b[:n])
}

type encodeFunc func(*encoder, value)

var (
	_ io.ReaderFrom   = (*encoder)(nil)
	_ io.Writer       = (*encoder)(nil)
	_ io.ByteWriter   = (*encoder)(nil)
	_ io.StringWriter = (*encoder)(nil)

	writerTo = reflect.TypeOf((*io.WriterTo)(nil)).Elem()
)

func encodeFuncOf(typ reflect.Type, version int16, flexible bool, tag structTag) encodeFunc {
	if reflect.PtrTo(typ).Implements(writerTo) {
		return writerEncodeFuncOf(typ)
	}
	switch typ.Kind() {
	case reflect.Bool:
		return (*encoder).encodeBool
	case reflect.Int8:
		return (*encoder).encodeInt8
	case reflect.Int16:
		return (*encoder).encodeInt16
	case reflect.Int32:
		return (*encoder).encodeInt32
	case reflect.Int64:
		return (*encoder).encodeInt64
	case reflect.String:
		return stringEncodeFuncOf(flexible, tag)
	case reflect.Struct:
		return structEncodeFuncOf(typ, version, flexible)
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 { // []byte
			return bytesEncodeFuncOf(flexible, tag)
		}
		return arrayEncodeFuncOf(typ, version, flexible, tag)
	default:
		panic("unsupported type: " + typ.String())
	}
}

func stringEncodeFuncOf(flexible bool, tag structTag) encodeFunc {
	switch {
	case flexible && tag.Nullable:
		// In flexible messages, all strings are compact
		return (*encoder).encodeCompactNullString
	case flexible:
		// In flexible messages, all strings are compact
		return (*encoder).encodeCompactString
	case tag.Nullable:
		return (*encoder).encodeNullString
	default:
		return (*encoder).encodeString
	}
}

func bytesEncodeFuncOf(flexible bool, tag structTag) encodeFunc {
	switch {
	case flexible && tag.Nullable:
		// In flexible messages, all arrays are compact
		return (*encoder).encodeCompactNullBytes
	case flexible:
		// In flexible messages, all arrays are compact
		return (*encoder).encodeCompactBytes
	case tag.Nullable:
		return (*encoder).encodeNullBytes
	default:
		return (*encoder).encodeBytes
	}
}

func structEncodeFuncOf(typ reflect.Type, version int16, flexible bool) encodeFunc {
	type field struct {
		encode encodeFunc
		index  index
		tagID  int
	}

	var fields []field
	var taggedFields []field

	forEachStructField(typ, func(typ reflect.Type, index index, tag string) {
		if typ.Size() != 0 { // skip struct{}
			forEachStructTag(tag, func(tag structTag) bool {
				if tag.MinVersion <= version && version <= tag.MaxVersion {
					f := field{
						encode: encodeFuncOf(typ, version, flexible, tag),
						index:  index,
						tagID:  tag.TagID,
					}

					if tag.TagID < -1 {
						// Normal required field
						fields = append(fields, f)
					} else {
						// Optional tagged field (flexible messages only)
						taggedFields = append(taggedFields, f)
					}
					return false
				}
				return true
			})
		}
	})

	return func(e *encoder, v value) {
		for i := range fields {
			f := &fields[i]
			f.encode(e, v.fieldByIndex(f.index))
		}

		if flexible {
			// See https://cwiki.apache.org/confluence/display/KAFKA/KIP-482%3A+The+Kafka+Protocol+should+Support+Optional+Tagged+Fields
			// for details of tag buffers in "flexible" messages.
			e.writeUnsignedVarInt(uint64(len(taggedFields)))

			for i := range taggedFields {
				f := &taggedFields[i]
				e.writeUnsignedVarInt(uint64(f.tagID))

				buf := &bytes.Buffer{}
				se := &encoder{writer: buf}
				f.encode(se, v.fieldByIndex(f.index))
				e.writeUnsignedVarInt(uint64(buf.Len()))
				e.Write(buf.Bytes())
			}
		}
	}
}

func arrayEncodeFuncOf(typ reflect.Type, version int16, flexible bool, tag structTag) encodeFunc {
	elemType := typ.Elem()
	elemFunc := encodeFuncOf(elemType, version, flexible, tag)
	switch {
	case flexible && tag.Nullable:
		// In flexible messages, all arrays are compact
		return func(e *encoder, v value) { e.encodeCompactNullArray(v, elemType, elemFunc) }
	case flexible:
		// In flexible messages, all arrays are compact
		return func(e *encoder, v value) { e.encodeCompactArray(v, elemType, elemFunc) }
	case tag.Nullable:
		return func(e *encoder, v value) { e.encodeNullArray(v, elemType, elemFunc) }
	default:
		return func(e *encoder, v value) { e.encodeArray(v, elemType, elemFunc) }
	}
}

func writerEncodeFuncOf(typ reflect.Type) encodeFunc {
	typ = reflect.PtrTo(typ)
	return func(e *encoder, v value) {
		// Optimization to write directly into the buffer when the encoder
		// does no need to compute a crc32 checksum.
		w := io.Writer(e)
		if e.table == nil {
			w = e.writer
		}
		_, err := v.iface(typ).(io.WriterTo).WriteTo(w)
		if err != nil {
			e.err = err
		}
	}
}

func writeInt8(b []byte, i int8) {
	b[0] = byte(i)
}

func writeInt16(b []byte, i int16) {
	binary.BigEndian.PutUint16(b, uint16(i))
}

func writeInt32(b []byte, i int32) {
	binary.BigEndian.PutUint32(b, uint32(i))
}

func writeInt64(b []byte, i int64) {
	binary.BigEndian.PutUint64(b, uint64(i))
}

func Marshal(version int16, value interface{}) ([]byte, error) {
	typ := typeOf(value)
	cache, _ := marshalers.Load().(map[versionedType]encodeFunc)
	key := versionedType{typ: typ, version: version}
	encode := cache[key]

	if encode == nil {
		encode = encodeFuncOf(reflect.TypeOf(value), version, false, structTag{
			MinVersion: -1,
			MaxVersion: -1,
			TagID:      -2,
			Compact:    true,
			Nullable:   true,
		})

		newCache := make(map[versionedType]encodeFunc, len(cache)+1)
		newCache[key] = encode

		for typ, fun := range cache {
			newCache[typ] = fun
		}

		marshalers.Store(newCache)
	}

	e, _ := encoders.Get().(*encoder)
	if e == nil {
		e = &encoder{writer: new(bytes.Buffer)}
	}

	b, _ := e.writer.(*bytes.Buffer)
	defer func() {
		b.Reset()
		e.Reset(b)
		encoders.Put(e)
	}()

	encode(e, nonAddressableValueOf(value))

	if e.err != nil {
		return nil, e.err
	}

	buf := b.Bytes()
	out := make([]byte, len(buf))
	copy(out, buf)
	return out, nil
}

type versionedType struct {
	typ     _type
	version int16
}

var (
	encoders   sync.Pool    // *encoder
	marshalers atomic.Value // map[versionedType]encodeFunc
)
