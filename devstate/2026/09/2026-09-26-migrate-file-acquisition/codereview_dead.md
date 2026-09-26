# Dead

1. [hard] Test-only new symbol — `pkg/acquisition/modules/file/tailwrapper/tailer.go:484` — `(*tailer).ForceRead` has no production callers; only `tailer_test.go` type-asserts to `*tailer` and invokes it for manual `PollInterval: -1` tests
   Quote:
   ```go
   // ForceRead is a test-only method that forces a read cycle
   func (t *tailer) ForceRead() {
       t.checkAndRead()
   }
   ```
   Note:
   ```
   rg ForceRead in worktree: definition in tailwrapper/tailer.go; callers only in tailwrapper/tailer_test.go (no non-test hits)
   ```
   Fix: Move `ForceRead` into the test file as a helper, or drive manual-mode tests through the production poll path instead of a production symbol
   Status: done
   Argument: Removed from `tailer.go`; `forceReadForTest` lives in `tailer_test.go`.
