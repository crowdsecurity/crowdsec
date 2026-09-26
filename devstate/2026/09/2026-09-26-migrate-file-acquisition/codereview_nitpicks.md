# Nitpicks

1. [hard] Clear conditions — `pkg/acquisition/modules/file/run.go:282` — `keepFileOpen := s.config.TailMode != "stat"` names the complement; the body maps default-mode handle strategy after configure-time validation to only `default` and `stat`
   Quote:
   ```go
   keepFileOpen := s.config.TailMode != "stat"

   pollInterval := time.Duration(0)
   if s.config.TailMode == "stat" {
       pollInterval = s.config.StatPollInterval
   }
   ```
   Fix: `keepFileOpen := s.config.TailMode == "default"` (or a predicate such as `isDefaultTailMode()`)
   Status: done
   Argument: Added `keepFileOpenForTailMode`; uses positive `tailMode == "default"`.

2. [hard] Symmetry and consistency — `pkg/acquisition/modules/file/tailwrapper/tailer.go:305` — sibling read paths both emit lines to `t.lines`, but keep-open mode delegates to `readLines()` while stat mode inlines an equivalent read-and-emit loop with different structure
   Quote:
   ```go
   func (t *tailer) readKeepOpenMode() {
       // ...
       t.readLines()
   }

   func (t *tailer) readStatMode() {
       // ...
       for {
           line, err := reader.ReadString('\n')
           if line != "" {
               // trim, select send to t.lines ...
           }
           if err != nil { /* EOF / error */ }
       }
   }
   ```
   Fix: extract one shared read-and-emit helper both modes call (e.g. `emitLinesFromReader`) so steps and channel-send shape match
   Status: done
   Argument: Both modes call `emitLinesFromReader`.

3. [hard] Name for the scope — `pkg/acquisition/modules/file/tailwrapper/tailer.go:483` — `ForceRead` is documented test-only but the identifier does not say test; callers reach it via `(*tailer)` type assert in tests
   Quote:
   ```go
   // ForceRead is a test-only method that forces a read cycle
   func (t *tailer) ForceRead() {
       t.checkAndRead()
   }
   ```
   Fix: rename to a test-scoped name such as `forceReadForTest` (or move behind a test helper in `tailer_test.go`)
   Status: done
   Argument: `forceReadForTest` helper in `tailer_test.go` only.
