# Tailwrapper

## Language

**Tailwrapper**:
In-house package under the file acquisition module that tails a single file with context cancellation. Replaces `github.com/nxadm/tail` for file datasource live mode.
_Avoid_: tail library, nxadm tail

**KeepFileOpen**:
Boolean in `tailwrapper.Config` selecting handle strategy. `true` keeps the file open and uses fsnotify or polling for changes; `false` stat-polls with open/read/close each cycle (network-share friendly).
_Avoid_: file handle mode

## Overview

Provides `TailFile(ctx, path, Config) (Tailer, error)` for one file. The file module maps `tail_mode: default` to `KeepFileOpen: true` and `tail_mode: stat` to `KeepFileOpen: false` with `PollInterval` from `stat_poll_interval`.

## How to use

- Call `tailwrapper.TailFile` with a cancellable context; stop via context cancel or `Tailer.Stop()`.
- Set `KeepFileOpen: true` for default-mode file acquisition (long-lived handle, fsnotify when `Poll: false`).
- Set `KeepFileOpen: false` with `Poll: true` and `PollInterval` for stat mode.
- Read lines from `Tailer.Lines()`; after `Dying()` closes, check `Tailer.Err()` for tailer death or file removal.

## Pattern snippet

```go
ctx, cancel := context.WithCancel(parent)
defer cancel()

tail, err := tailwrapper.TailFile(ctx, path, tailwrapper.Config{
    ReOpen:       true,
    Poll:         pollFile,
    PollInterval: pollInterval,
    Location:     &tailwrapper.SeekInfo{Offset: 0, Whence: io.SeekEnd},
    KeepFileOpen: keepFileOpen,
})
if err != nil {
    return err
}
defer tail.Stop()

for {
    select {
    case <-ctx.Done():
        return nil
    case line := <-tail.Lines():
        if line == nil {
            continue
        }
        // emit line.Text
    }
}
```

## Key files

- `pkg/acquisition/modules/file/tailwrapper/interface.go` — `Tailer`, `Config`, `Line`, `SeekInfo`
- `pkg/acquisition/modules/file/tailwrapper/tailer.go` — unified tailer implementation

## Gotchas

- File must exist at `TailFile` start (validated via `os.Stat`).
- `PollInterval` of `-1` is manual/test mode (no automatic ticker in the main loop).
- `PollInterval` of `0` defaults to 1s inside the tailer.
- Bytes that do not end in a newline are not sent. The read position stays in front of that fragment until a newline arrives. Truncation that shrinks the file drops the fragment.
