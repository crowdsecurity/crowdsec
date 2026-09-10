// wasm_memory.go backs the obfuscator's wasm linear memory with an anonymous
// mapping instead of the Go heap. The guest grows its memory one 64KB page at a
// time — ~640 grow calls for a single obfuscation — and wazero's default
// allocator reallocates and copies a Go slice on each one, churning ~190MB of
// heap per run to reach a ~48MB result. Here the whole reservation is mapped
// once and handed out as slices of itself: pages become resident only as the
// guest touches them, and the mapping goes back to the OS when the module
// closes.
package challenge

import (
	"context"

	log "github.com/sirupsen/logrus"
	"github.com/tetratelabs/wazero/experimental"
)

// wasmMemoryReservation is the address space reserved per obfuscation. The
// reservation itself costs no memory — only touched pages become resident — so
// it is sized well past what the obfuscator needs: measured peaks are ~49MB for
// the per-epoch key module and ~87MB for the full challenge bundle (the
// fallback path). Peak scales with input size, and both inputs are fixed by the
// code, never by a request. A guest asking past the reservation fails its grow,
// which surfaces as an ObfuscateJS error rather than a crash.
const wasmMemoryReservation = 512 << 20

// wasmMemoryFallbackInitial is the first allocation of the heap-backed
// fallback, sized past the measured peak so the common case never reallocates.
const wasmMemoryFallbackInitial = 64 << 20

// withWasmMemoryAllocator installs the linear-memory allocator used for every
// module instantiated from ctx.
func withWasmMemoryAllocator(ctx context.Context) context.Context {
	return experimental.WithMemoryAllocator(ctx, wasmMemoryAllocator{})
}

// wasmMemoryAllocator hands out the buffers below. It is stateless: each
// instantiation gets its own mapping, freed when that module closes.
//
// Buffers are deliberately not pooled across instantiations. A fresh mapping
// (or make) is zeroed, which is what lets Reallocate expose the grown tail
// as-is; reusing one would hand the next guest the previous epoch's HMAC key
// unless it were wiped first.
type wasmMemoryAllocator struct{}

// Allocate implements experimental.MemoryAllocator. wazero passes the module's
// declared initial memory as a sizing hint (1.4MB here) — ignored, since taking
// it is what leads the guest to grow page by page; guestMax is the most it may
// ever ask for.
func (wasmMemoryAllocator) Allocate(_, guestMax uint64) experimental.LinearMemory {
	size := min(uint64(wasmMemoryReservation), guestMax)

	res, err := reserveWasmMemory(size)
	if err != nil {
		// No mapping (unsupported platform, or strict overcommit refusing the
		// reservation): the heap-backed fallback still works, it just costs more.
		log.WithError(err).Debug("cannot map wasm linear memory, falling back to the Go heap")

		return &heapMemory{}
	}

	return &mappedMemory{res: res}
}

// mappedMemory implements experimental.LinearMemory by serving the guest slices
// of one fixed mapping.
type mappedMemory struct {
	res []byte
}

// Reallocate re-slices the mapping rather than allocating: a grow must keep
// everything the guest already wrote, so every call returns the same bytes with
// a longer tail. Only that tail is new, and it is still zero — wasm memory only
// grows, and the guest could not address past its previous length.
func (m *mappedMemory) Reallocate(size uint64) []byte {
	if size > uint64(len(m.res)) {
		return nil
	}

	return m.res[:size]
}

func (m *mappedMemory) Free() {
	if m.res == nil {
		return
	}

	if err := releaseWasmMemory(m.res); err != nil {
		log.WithError(err).Error("failed to release wasm linear memory")
	}

	m.res = nil
}

// heapMemory implements experimental.LinearMemory as the portable fallback: a
// Go slice grown geometrically, so a guest that grows page by page doesn't pay
// a copy per page.
type heapMemory struct {
	buf []byte
}

// Reallocate grows the buffer, copying when it must: like the mapped
// implementation, the bytes the guest already wrote have to survive the grow.
func (m *heapMemory) Reallocate(size uint64) []byte {
	if size > uint64(cap(m.buf)) {
		buf := make([]byte, size, max(2*size, wasmMemoryFallbackInitial))
		copy(buf, m.buf)
		m.buf = buf
	}

	// Bytes past the old length are zero, from make: the buffer only ever
	// grows, so the guest never sees anything it didn't write itself.
	m.buf = m.buf[:size]

	return m.buf
}

func (m *heapMemory) Free() {
	m.buf = nil
}
