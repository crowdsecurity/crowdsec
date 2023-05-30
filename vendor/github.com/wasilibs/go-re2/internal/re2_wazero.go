//go:build !tinygo.wasm && !re2_cgo

package internal

import (
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

var (
	errFailedWrite = errors.New("failed to read from wasm memory")
	errFailedRead  = errors.New("failed to read from wasm memory")
)

//go:embed wasm/libcre2.so
var libre2 []byte

var (
	wasmRT       wazero.Runtime
	wasmCompiled wazero.CompiledModule
)

type libre2ABI struct {
	cre2New                   api.Function
	cre2Delete                api.Function
	cre2Match                 api.Function
	cre2PartialMatch          api.Function
	cre2FindAndConsume        api.Function
	cre2NumCapturingGroups    api.Function
	cre2ErrorCode             api.Function
	cre2ErrorArg              api.Function
	cre2NamedGroupsIterNew    api.Function
	cre2NamedGroupsIterNext   api.Function
	cre2NamedGroupsIterDelete api.Function
	cre2GlobalReplace         api.Function
	cre2OptNew                api.Function
	cre2OptDelete             api.Function
	cre2OptSetLogErrors       api.Function
	cre2OptSetLongestMatch    api.Function
	cre2OptSetPosixSyntax     api.Function
	cre2OptSetCaseSensitive   api.Function
	cre2OptSetLatin1Encoding  api.Function

	malloc api.Function
	free   api.Function

	wasmMemory api.Memory

	mod api.Module

	memory sharedMemory
	mu     sync.Mutex
}

func init() {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)

	wasi_snapshot_preview1.MustInstantiate(ctx, rt)

	code, err := rt.CompileModule(ctx, libre2)
	if err != nil {
		panic(err)
	}
	wasmCompiled = code

	wasmRT = rt
}

var moduleIdx = uint64(0)

func newABI() *libre2ABI {
	ctx := context.Background()
	modIdx := atomic.AddUint64(&moduleIdx, 1)
	mod, err := wasmRT.InstantiateModule(ctx, wasmCompiled, wazero.NewModuleConfig().WithName(strconv.FormatUint(modIdx, 10)))
	if err != nil {
		panic(err)
	}

	abi := &libre2ABI{
		cre2New:                   mod.ExportedFunction("cre2_new"),
		cre2Delete:                mod.ExportedFunction("cre2_delete"),
		cre2Match:                 mod.ExportedFunction("cre2_match"),
		cre2PartialMatch:          mod.ExportedFunction("cre2_partial_match_re"),
		cre2FindAndConsume:        mod.ExportedFunction("cre2_find_and_consume_re"),
		cre2NumCapturingGroups:    mod.ExportedFunction("cre2_num_capturing_groups"),
		cre2ErrorCode:             mod.ExportedFunction("cre2_error_code"),
		cre2ErrorArg:              mod.ExportedFunction("cre2_error_arg"),
		cre2NamedGroupsIterNew:    mod.ExportedFunction("cre2_named_groups_iter_new"),
		cre2NamedGroupsIterNext:   mod.ExportedFunction("cre2_named_groups_iter_next"),
		cre2NamedGroupsIterDelete: mod.ExportedFunction("cre2_named_groups_iter_delete"),
		cre2GlobalReplace:         mod.ExportedFunction("cre2_global_replace_re"),
		cre2OptNew:                mod.ExportedFunction("cre2_opt_new"),
		cre2OptDelete:             mod.ExportedFunction("cre2_opt_delete"),
		cre2OptSetLogErrors:       mod.ExportedFunction("cre2_opt_set_log_errors"),
		cre2OptSetLongestMatch:    mod.ExportedFunction("cre2_opt_set_longest_match"),
		cre2OptSetPosixSyntax:     mod.ExportedFunction("cre2_opt_set_posix_syntax"),
		cre2OptSetCaseSensitive:   mod.ExportedFunction("cre2_opt_set_case_sensitive"),
		cre2OptSetLatin1Encoding:  mod.ExportedFunction("cre2_opt_set_latin1_encoding"),

		malloc: mod.ExportedFunction("malloc"),
		free:   mod.ExportedFunction("free"),

		wasmMemory: mod.Memory(),
		mod:        mod,
	}

	return abi
}

func (abi *libre2ABI) startOperation(memorySize int) {
	abi.mu.Lock()
	abi.memory.reserve(abi, uint32(memorySize))
}

func (abi *libre2ABI) endOperation() {
	abi.mu.Unlock()
}

func newRE(abi *libre2ABI, pattern cString, opts CompileOptions) uintptr {
	ctx := context.Background()
	res, err := abi.cre2OptNew.Call(ctx)
	if err != nil {
		panic(err)
	}
	optPtr := uintptr(res[0])
	defer func() {
		if _, err := abi.cre2OptDelete.Call(ctx, uint64(optPtr)); err != nil {
			panic(err)
		}
	}()
	if _, err := abi.cre2OptSetLogErrors.Call(ctx, uint64(optPtr), 0); err != nil {
		panic(err)
	}
	if opts.Longest {
		_, err = abi.cre2OptSetLongestMatch.Call(ctx, uint64(optPtr), 1)
		if err != nil {
			panic(err)
		}
	}
	if opts.Posix {
		_, err = abi.cre2OptSetPosixSyntax.Call(ctx, uint64(optPtr), 1)
		if err != nil {
			panic(err)
		}
	}
	if opts.CaseInsensitive {
		_, err = abi.cre2OptSetCaseSensitive.Call(ctx, uint64(optPtr), 0)
		if err != nil {
			panic(err)
		}
	}
	if opts.Latin1 {
		_, err = abi.cre2OptSetLatin1Encoding.Call(ctx, uint64(optPtr))
		if err != nil {
			panic(err)
		}
	}
	res, err = abi.cre2New.Call(ctx, uint64(pattern.ptr), uint64(pattern.length), uint64(optPtr))
	if err != nil {
		panic(err)
	}
	return uintptr(res[0])
}

func reError(abi *libre2ABI, rePtr uintptr) (int, string) {
	ctx := context.Background()
	res, err := abi.cre2ErrorCode.Call(ctx, uint64(rePtr))
	if err != nil {
		panic(err)
	}
	code := int(res[0])
	if code == 0 {
		return 0, ""
	}

	argPtr := newCStringArray(abi, 1)
	_, err = abi.cre2ErrorArg.Call(ctx, uint64(rePtr), uint64(argPtr.ptr))
	if err != nil {
		panic(err)
	}
	sPtr := binary.LittleEndian.Uint32(abi.memory.read(abi, argPtr.ptr, 4))
	sLen := binary.LittleEndian.Uint32(abi.memory.read(abi, argPtr.ptr+4, 4))

	return code, string(abi.memory.read(abi, uintptr(sPtr), int(sLen)))
}

func numCapturingGroups(abi *libre2ABI, rePtr uintptr) int {
	ctx := context.Background()
	res, err := abi.cre2NumCapturingGroups.Call(ctx, uint64(rePtr))
	if err != nil {
		panic(err)
	}
	return int(res[0])
}

func deleteRE(abi *libre2ABI, rePtr uintptr) {
	ctx := context.Background()
	if _, err := abi.cre2Delete.Call(ctx, uint64(rePtr)); err != nil {
		panic(err)
	}
}

func release(re *Regexp) {
	ctx := context.Background()
	deleteRE(re.abi, re.ptr)
	if err := re.abi.mod.Close(ctx); err != nil {
		fmt.Printf("error closing wazero module: %v", err)
	}
}

func match(re *Regexp, s cString, matchesPtr uintptr, nMatches uint32) bool {
	ctx := context.Background()
	res, err := re.abi.cre2Match.Call(ctx, uint64(re.ptr), uint64(s.ptr), uint64(s.length), 0, uint64(s.length), 0, uint64(matchesPtr), uint64(nMatches))
	if err != nil {
		panic(err)
	}

	return res[0] == 1
}

func matchFrom(re *Regexp, s cString, startPos int, matchesPtr uintptr, nMatches uint32) bool {
	ctx := context.Background()
	res, err := re.abi.cre2Match.Call(ctx, uint64(re.ptr), uint64(s.ptr), uint64(s.length), uint64(startPos), uint64(s.length), 0, uint64(matchesPtr), uint64(nMatches))
	if err != nil {
		panic(err)
	}

	return res[0] == 1
}

func readMatch(abi *libre2ABI, cs cString, matchPtr uintptr, dstCap []int) []int {
	matchBuf := abi.memory.read(abi, matchPtr, 8)
	subStrPtr := uintptr(binary.LittleEndian.Uint32(matchBuf))
	sLen := uintptr(binary.LittleEndian.Uint32(matchBuf[4:]))
	sIdx := subStrPtr - cs.ptr

	return append(dstCap, int(sIdx), int(sIdx+sLen))
}

func readMatches(abi *libre2ABI, cs cString, matchesPtr uintptr, n int, deliver func([]int)) {
	var dstCap [2]int

	matchesBuf := abi.memory.read(abi, matchesPtr, 8*n)
	for i := 0; i < n; i++ {
		subStrPtr := uintptr(binary.LittleEndian.Uint32(matchesBuf[8*i:]))
		if subStrPtr == 0 {
			deliver(append(dstCap[:0], -1, -1))
			continue
		}
		sLen := uintptr(binary.LittleEndian.Uint32(matchesBuf[8*i+4:]))
		sIdx := subStrPtr - cs.ptr
		deliver(append(dstCap[:0], int(sIdx), int(sIdx+sLen)))
	}
}

func namedGroupsIter(abi *libre2ABI, rePtr uintptr) uintptr {
	ctx := context.Background()

	res, err := abi.cre2NamedGroupsIterNew.Call(ctx, uint64(rePtr))
	if err != nil {
		panic(err)
	}

	return uintptr(res[0])
}

func namedGroupsIterNext(abi *libre2ABI, iterPtr uintptr) (string, int, bool) {
	ctx := context.Background()

	// Not on the hot path so don't bother optimizing this yet.
	ptrs := malloc(abi, 8)
	defer free(abi, ptrs)
	namePtrPtr := ptrs
	indexPtr := namePtrPtr + 4

	res, err := abi.cre2NamedGroupsIterNext.Call(ctx, uint64(iterPtr), uint64(namePtrPtr), uint64(indexPtr))
	if err != nil {
		panic(err)
	}

	if res[0] == 0 {
		return "", 0, false
	}

	namePtr, ok := abi.wasmMemory.ReadUint32Le(uint32(namePtrPtr))
	if !ok {
		panic(errFailedRead)
	}

	// C-string, read content until NULL.
	name := strings.Builder{}
	for {
		b, ok := abi.wasmMemory.ReadByte(namePtr)
		if !ok {
			panic(errFailedRead)
		}
		if b == 0 {
			break
		}
		name.WriteByte(b)
		namePtr++
	}

	index, ok := abi.wasmMemory.ReadUint32Le(uint32(indexPtr))
	if !ok {
		panic(errFailedRead)
	}

	return name.String(), int(index), true
}

func namedGroupsIterDelete(abi *libre2ABI, iterPtr uintptr) {
	ctx := context.Background()

	_, err := abi.cre2NamedGroupsIterDelete.Call(ctx, uint64(iterPtr))
	if err != nil {
		panic(err)
	}
}

func globalReplace(re *Regexp, textAndTargetPtr uintptr, rewritePtr uintptr) ([]byte, bool) {
	ctx := context.Background()

	res, err := re.abi.cre2GlobalReplace.Call(ctx, uint64(re.ptr), uint64(textAndTargetPtr), uint64(rewritePtr))
	if err != nil {
		panic(err)
	}

	if int64(res[0]) == -1 {
		panic("out of memory")
	}

	if res[0] == 0 {
		// No replacements
		return nil, false
	}

	strPtr, ok := re.abi.wasmMemory.ReadUint32Le(uint32(textAndTargetPtr))
	if !ok {
		panic(errFailedRead)
	}
	// This was malloc'd by cre2, so free it
	defer free(re.abi, uintptr(strPtr))

	strLen, ok := re.abi.wasmMemory.ReadUint32Le(uint32(textAndTargetPtr + 4))
	if !ok {
		panic(errFailedRead)
	}

	str, ok := re.abi.wasmMemory.Read(strPtr, strLen)
	if !ok {
		panic(errFailedRead)
	}

	// Read returns a view, so make sure to copy it
	return append([]byte{}, str...), true
}

type cString struct {
	ptr    uintptr
	length int
}

func newCString(abi *libre2ABI, s string) cString {
	ptr := abi.memory.writeString(abi, s)
	return cString{
		ptr:    ptr,
		length: len(s),
	}
}

func newCStringFromBytes(abi *libre2ABI, s []byte) cString {
	ptr := abi.memory.write(abi, s)
	return cString{
		ptr:    ptr,
		length: len(s),
	}
}

func newCStringPtr(abi *libre2ABI, cs cString) pointer {
	ptr := abi.memory.allocate(8)
	if !abi.wasmMemory.WriteUint32Le(uint32(ptr), uint32(cs.ptr)) {
		panic(errFailedWrite)
	}
	if !abi.wasmMemory.WriteUint32Le(uint32(ptr+4), uint32(cs.length)) {
		panic(errFailedWrite)
	}
	return pointer{ptr: ptr, abi: abi}
}

type cStringArray struct {
	ptr uintptr
}

func newCStringArray(abi *libre2ABI, n int) cStringArray {
	ptr := abi.memory.allocate(uint32(n * 8))
	return cStringArray{ptr: ptr}
}

type pointer struct {
	ptr uintptr
	abi *libre2ABI
}

func malloc(abi *libre2ABI, size uint32) uintptr {
	res, err := abi.malloc.Call(context.Background(), uint64(size))
	if err != nil {
		panic(err)
	}
	return uintptr(res[0])
}

func free(abi *libre2ABI, ptr uintptr) {
	_, err := abi.free.Call(context.Background(), uint64(ptr))
	if err != nil {
		panic(err)
	}
}

type sharedMemory struct {
	size    uint32
	bufPtr  uint32
	nextIdx uint32
}

func (m *sharedMemory) reserve(abi *libre2ABI, size uint32) {
	m.nextIdx = 0
	if m.size >= size {
		return
	}

	ctx := context.Background()
	if m.bufPtr != 0 {
		_, err := abi.free.Call(ctx, uint64(m.bufPtr))
		if err != nil {
			panic(err)
		}
	}

	res, err := abi.malloc.Call(ctx, uint64(size))
	if err != nil {
		panic(err)
	}

	m.size = size
	m.bufPtr = uint32(res[0])
}

func (m *sharedMemory) allocate(size uint32) uintptr {
	if m.nextIdx+size > m.size {
		panic("not enough reserved shared memory")
	}

	ptr := m.bufPtr + m.nextIdx
	m.nextIdx += size
	return uintptr(ptr)
}

func (m *sharedMemory) read(abi *libre2ABI, ptr uintptr, size int) []byte {
	buf, ok := abi.wasmMemory.Read(uint32(ptr), uint32(size))
	if !ok {
		panic(errFailedRead)
	}
	return buf
}

func (m *sharedMemory) write(abi *libre2ABI, b []byte) uintptr {
	ptr := m.allocate(uint32(len(b)))
	abi.wasmMemory.Write(uint32(ptr), b)
	return ptr
}

func (m *sharedMemory) writeString(abi *libre2ABI, s string) uintptr {
	ptr := m.allocate(uint32(len(s)))
	abi.wasmMemory.WriteString(uint32(ptr), s)
	return ptr
}
