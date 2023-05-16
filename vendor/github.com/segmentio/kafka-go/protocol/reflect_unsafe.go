//go:build unsafe
// +build unsafe

package protocol

import (
	"reflect"
	"unsafe"
)

type iface struct {
	typ unsafe.Pointer
	ptr unsafe.Pointer
}

type slice struct {
	ptr unsafe.Pointer
	len int
	cap int
}

type index uintptr

type _type struct {
	ptr unsafe.Pointer
}

func typeOf(x interface{}) _type {
	return _type{ptr: ((*iface)(unsafe.Pointer(&x))).typ}
}

func elemTypeOf(x interface{}) _type {
	return makeType(reflect.TypeOf(x).Elem())
}

func makeType(t reflect.Type) _type {
	return _type{ptr: ((*iface)(unsafe.Pointer(&t))).ptr}
}

type value struct {
	ptr unsafe.Pointer
}

func nonAddressableValueOf(x interface{}) value {
	return valueOf(x)
}

func valueOf(x interface{}) value {
	return value{ptr: ((*iface)(unsafe.Pointer(&x))).ptr}
}

func makeValue(t reflect.Type) value {
	return value{ptr: unsafe.Pointer(reflect.New(t).Pointer())}
}

func (v value) bool() bool { return *(*bool)(v.ptr) }

func (v value) int8() int8 { return *(*int8)(v.ptr) }

func (v value) int16() int16 { return *(*int16)(v.ptr) }

func (v value) int32() int32 { return *(*int32)(v.ptr) }

func (v value) int64() int64 { return *(*int64)(v.ptr) }

func (v value) string() string { return *(*string)(v.ptr) }

func (v value) bytes() []byte { return *(*[]byte)(v.ptr) }

func (v value) iface(t reflect.Type) interface{} {
	return *(*interface{})(unsafe.Pointer(&iface{
		typ: ((*iface)(unsafe.Pointer(&t))).ptr,
		ptr: v.ptr,
	}))
}

func (v value) array(t reflect.Type) array {
	return array{
		size: uintptr(t.Size()),
		elem: ((*slice)(v.ptr)).ptr,
		len:  ((*slice)(v.ptr)).len,
	}
}

func (v value) setBool(b bool) { *(*bool)(v.ptr) = b }

func (v value) setInt8(i int8) { *(*int8)(v.ptr) = i }

func (v value) setInt16(i int16) { *(*int16)(v.ptr) = i }

func (v value) setInt32(i int32) { *(*int32)(v.ptr) = i }

func (v value) setInt64(i int64) { *(*int64)(v.ptr) = i }

func (v value) setString(s string) { *(*string)(v.ptr) = s }

func (v value) setBytes(b []byte) { *(*[]byte)(v.ptr) = b }

func (v value) setArray(a array) { *(*slice)(v.ptr) = slice{ptr: a.elem, len: a.len, cap: a.len} }

func (v value) fieldByIndex(i index) value {
	return value{ptr: unsafe.Pointer(uintptr(v.ptr) + uintptr(i))}
}

type array struct {
	elem unsafe.Pointer
	size uintptr
	len  int
}

var (
	emptyArray struct{}
)

func makeArray(t reflect.Type, n int) array {
	var elem unsafe.Pointer
	var size = uintptr(t.Size())
	if n == 0 {
		elem = unsafe.Pointer(&emptyArray)
	} else {
		elem = unsafe_NewArray(((*iface)(unsafe.Pointer(&t))).ptr, n)
	}
	return array{elem: elem, size: size, len: n}
}

func (a array) index(i int) value {
	return value{ptr: unsafe.Pointer(uintptr(a.elem) + (uintptr(i) * a.size))}
}

func (a array) length() int { return a.len }

func (a array) isNil() bool { return a.elem == nil }

func indexOf(s reflect.StructField) index { return index(s.Offset) }

func bytesToString(b []byte) string { return *(*string)(unsafe.Pointer(&b)) }

//go:linkname unsafe_NewArray reflect.unsafe_NewArray
func unsafe_NewArray(rtype unsafe.Pointer, length int) unsafe.Pointer
