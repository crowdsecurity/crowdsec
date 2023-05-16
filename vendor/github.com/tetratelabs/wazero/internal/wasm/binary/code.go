package binary

import (
	"bytes"
	"fmt"
	"io"
	"math"

	"github.com/tetratelabs/wazero/internal/leb128"
	"github.com/tetratelabs/wazero/internal/wasm"
)

func decodeCode(r *bytes.Reader, codeSectionStart uint64, ret *wasm.Code) (err error) {
	ss, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return fmt.Errorf("get the size of code: %w", err)
	}
	remaining := int64(ss)

	// parse locals
	ls, bytesRead, err := leb128.DecodeUint32(r)
	remaining -= int64(bytesRead)
	if err != nil {
		return fmt.Errorf("get the size locals: %v", err)
	} else if remaining < 0 {
		return io.EOF
	}

	var nums []uint64
	var types []wasm.ValueType
	var sum uint64
	var n uint32
	for i := uint32(0); i < ls; i++ {
		n, bytesRead, err = leb128.DecodeUint32(r)
		remaining -= int64(bytesRead) + 1 // +1 for the subsequent ReadByte
		if err != nil {
			return fmt.Errorf("read n of locals: %v", err)
		} else if remaining < 0 {
			return io.EOF
		}

		sum += uint64(n)
		nums = append(nums, uint64(n))

		b, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("read type of local: %v", err)
		}
		switch vt := b; vt {
		case wasm.ValueTypeI32, wasm.ValueTypeF32, wasm.ValueTypeI64, wasm.ValueTypeF64,
			wasm.ValueTypeFuncref, wasm.ValueTypeExternref, wasm.ValueTypeV128:
			types = append(types, vt)
		default:
			return fmt.Errorf("invalid local type: 0x%x", vt)
		}
	}

	if sum > math.MaxUint32 {
		return fmt.Errorf("too many locals: %d", sum)
	}

	var localTypes []wasm.ValueType
	for i, num := range nums {
		t := types[i]
		for j := uint64(0); j < num; j++ {
			localTypes = append(localTypes, t)
		}
	}

	bodyOffsetInCodeSection := codeSectionStart - uint64(r.Len())
	body := make([]byte, remaining)
	if _, err = io.ReadFull(r, body); err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	if endIndex := len(body) - 1; endIndex < 0 || body[endIndex] != wasm.OpcodeEnd {
		return fmt.Errorf("expr not end with OpcodeEnd")
	}

	ret.BodyOffsetInCodeSection = bodyOffsetInCodeSection
	ret.LocalTypes = localTypes
	ret.Body = body
	return nil
}
