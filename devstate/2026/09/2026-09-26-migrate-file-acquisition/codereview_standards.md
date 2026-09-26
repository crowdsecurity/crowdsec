# Standards

1. [hard] Name for the scope — `pkg/acquisition/modules/file/tailwrapper/tailer.go:484` — `ForceRead` is test-only but the identifier does not say test
   Fix: Rename to `forceReadForTest` (or move manual-read driving into `_test.go` helpers)
   Status: done
   Argument: Moved to `forceReadForTest` helper in `tailwrapper/tailer_test.go`; removed from `tailer.go`.
2. [hard] Leave a trail — `pkg/acquisition/modules/file/run.go:56` — `Stream` replaces `StreamingAcquisition` with no succinct job comment on the method
   Fix: Add a one-line doc comment stating that it tails configured files until ctx is canceled
   Status: done
   Argument: Added `Stream` doc comment on `run.go`.
3. [judgement] Duplicated Code — `pkg/acquisition/modules/file/tailwrapper/tailer.go:349` — `readStatMode` and `readLines` repeat the same read/trim/emit loop
   Fix: Extract a shared helper that reads from a `*bufio.Reader` and emits `*Line` values on `t.lines`
   Status: done
   Argument: Extracted `emitLinesFromReader`; shared by both read paths.
