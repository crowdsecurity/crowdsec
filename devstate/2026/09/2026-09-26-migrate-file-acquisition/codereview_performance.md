# Performance

1. [hard] Goroutine or timer per item — `pkg/acquisition/modules/file/tailwrapper/tailer.go:453` — `handleFileRemoved` uses `time.After` inside a `for` loop while waiting for a deleted file to reappear; each iteration allocates a timer until it fires, so wait duration grows timer churn on the rotation path
   Quote:
   ```go
   for {
       select {
       case <-t.done:
           return
       case <-time.After(100 * time.Millisecond):
           fi, err := os.Stat(t.filename)
   ```
   Fix: Use one `time.NewTicker(100 * time.Millisecond)` with `defer ticker.Stop()`, or reuse a single `time.Timer` and reset it each iteration
   Status: done
   Argument: Replaced loop `time.After` with one `time.NewTicker`.
