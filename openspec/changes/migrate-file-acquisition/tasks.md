## 1. Configuration

- [ ] 1.1 Add `tail_mode` and `stat_poll_interval` fields to `Configuration` in `config.go`
- [ ] 1.2 Validate `tail_mode` (`default`, `stat`, or empty); reject unknown values at configure time
- [ ] 1.3 Normalize `stat_poll_interval` (default 1s, `0` → 1s, `-1` manual); ignore when `tail_mode` is default

## 2. tailwrapper package

- [ ] 2.1 Create `pkg/acquisition/modules/file/tailwrapper` with `Config`, `SeekInfo`, `Line`, and `Tailer` interface
- [ ] 2.2 Implement `TailFile(ctx, filename, Config) (Tailer, error)` factory selecting strategy from `KeepFileOpen`
- [ ] 2.3 Implement default (open-handle) tailer: follow, reopen-on-rotate, poll/inotify flag from caller — parity with nxadm behaviour
- [ ] 2.4 Implement stat tailer: stat-size loop, open/read/close between polls, honour `ctx` cancel and poll interval
- [ ] 2.5 Add unit tests for both tailers (rotation, truncate, context cancel, manual `-1` interval)

## 3. File module migration

- [ ] 3.1 Implement `Stream(ctx, out)` on `Source` using `errgroup`; refactor `monitorNewFiles` and `setupTailForFile` to use `context.Context`
- [ ] 3.2 Wire `setupTailForFile` to `tailwrapper.TailFile` with `KeepFileOpen` from `tail_mode`
- [ ] 3.3 Map existing poll/inotify/network-FS logic into tailwrapper `Config` for default mode
- [ ] 3.4 Remove `StreamingAcquisition` and `Tailer` interface compliance from `init.go`; assert `RestartableStreamer` instead
- [ ] 3.5 Ensure metrics, labels, exclude regexps, and line trimming unchanged

## 4. Dependency and tests

- [ ] 4.1 Remove `github.com/nxadm/tail` import from `run.go` and drop module from `go.mod` / `go.sum`
- [ ] 4.2 Add `tail_modes_test.go` covering default vs stat config selection
- [ ] 4.3 Update `file_test.go` live-acquisition tests to use `Stream(ctx, out)` where applicable
- [ ] 4.4 Run `go test -count=1 ./pkg/acquisition/modules/file/...` and fix regressions

## 5. Documentation

- [ ] 5.1 Document optional `tail_mode` and `stat_poll_interval` in file acquisition config comments or operator-facing docs touched by this module
