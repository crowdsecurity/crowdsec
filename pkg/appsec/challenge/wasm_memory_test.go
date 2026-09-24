package challenge

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero/experimental"
)

// Allocate must always hand back a usable LinearMemory: on a platform (or a
// machine) where the mapping is refused it falls back to the heap.
func TestWasmMemoryAllocate(t *testing.T) {
	mem := wasmMemoryAllocator{}.Allocate(0, wasmMemoryReservation)
	defer mem.Free()

	require.NotNil(t, mem)
	require.Len(t, mem.Reallocate(64<<10), 64<<10)
}

func TestWasmMemoryReallocate(t *testing.T) {
	res, err := reserveWasmMemory(1 << 20)

	mapped := experimental.LinearMemory(&mappedMemory{res: res})
	if err != nil {
		t.Log("no mapping on this platform, testing the heap fallback only:", err)
		mapped = nil
	}

	for name, mem := range map[string]experimental.LinearMemory{"mapped": mapped, "heap": &heapMemory{}} {
		if mem == nil {
			continue
		}

		t.Run(name, func(t *testing.T) {
			defer mem.Free()

			first := mem.Reallocate(64 << 10)
			require.Len(t, first, 64<<10)
			require.Equal(t, make([]byte, 64<<10), first, "a fresh linear memory must be zeroed")

			first[0] = 0x42
			first[64<<10-1] = 0x43

			grown := mem.Reallocate(128 << 10)
			require.Len(t, grown, 128<<10)
			require.Equal(t, byte(0x42), grown[0], "growth must preserve what the guest wrote")
			require.Equal(t, byte(0x43), grown[64<<10-1])
			require.Equal(t, make([]byte, 64<<10), grown[64<<10:], "bytes past the old length must be zeroed")
		})
	}
}

// A guest that grows past the reservation gets a nil buffer, which wazero turns
// into a failed grow — the alternative would be serving it memory it can't have.
func TestMappedMemoryRefusesGrowthPastReservation(t *testing.T) {
	res, err := reserveWasmMemory(1 << 20)
	if err != nil {
		t.Skip("no anonymous mapping on this platform:", err)
	}

	mem := &mappedMemory{res: res}
	defer mem.Free()

	require.Len(t, mem.Reallocate(1<<20), 1<<20)
	require.Nil(t, mem.Reallocate(1<<20+1))
}

// Free is called on every module close, and Close is reachable more than once.
func TestMappedMemoryFreeIsIdempotent(t *testing.T) {
	res, err := reserveWasmMemory(1 << 20)
	if err != nil {
		t.Skip("no anonymous mapping on this platform:", err)
	}

	mem := &mappedMemory{res: res}
	mem.Free()
	require.NotPanics(t, mem.Free)
}
