package protocol

import (
	"math/bits"
)

func sizeOfVarString(s string) int {
	return sizeOfVarInt(int64(len(s))) + len(s)
}

func sizeOfVarNullBytes(b []byte) int {
	if b == nil {
		return sizeOfVarInt(-1)
	}
	n := len(b)
	return sizeOfVarInt(int64(n)) + n
}

func sizeOfVarNullBytesIface(b Bytes) int {
	if b == nil {
		return sizeOfVarInt(-1)
	}
	n := b.Len()
	return sizeOfVarInt(int64(n)) + n
}

func sizeOfVarInt(i int64) int {
	return sizeOfUnsignedVarInt(uint64((i << 1) ^ (i >> 63))) // zig-zag encoding
}

func sizeOfUnsignedVarInt(i uint64) int {
	return (bits.Len64(i|1) + 6) / 7
}
