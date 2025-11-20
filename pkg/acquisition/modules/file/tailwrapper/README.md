# Tail Wrapper Package

This package provides a unified interface for file tailing with multiple implementations.

## Purpose

The wrapper pattern allows switching between different file tailing strategies based on configuration, addressing the issue of keeping file handles open for extended periods (especially problematic on SMB/Samba network shares).

## Implementations

### 1. Native (`nxadm`) Tail
- Wraps `github.com/nxadm/tail` library
- Keeps file handles open continuously
- Uses inotify or polling to detect changes
- Default mode for backward compatibility

### 2. Stat-Based Tail
- Doesn't keep file handles open
- Uses `os.Stat()` to detect file changes
- Opens file, reads new data, closes immediately
- Designed for network shares (SMB/Samba) where keeping handles open is problematic
- Detects truncation via file size comparison (no inode tracking)
- Uses `bufio.Reader.ReadString()` like native tail (no line size limits)

## Configuration

Add to your file acquisition configuration:

```yaml
filenames:
  - /path/to/logs/*.log
tail_mode: stat              # "native" (default) or "stat"
stat_poll_interval: 1s       # How often to check for changes (stat mode only)
```

### Configuration Options

- `tail_mode`: 
  - `"native"` or `"nxadm"` (default): Use the original tail library (keeps file handles open)
  - `"stat"`: Use stat-based polling (closes handles after reading)
  
- `stat_poll_interval`: (only used when `tail_mode: stat`)
  - Default: `1s`
  - `0`: Uses default of 1 second
  - `-1`: Manual mode (no automatic polling, for testing only)
  - Any positive duration: Custom polling interval

## Architecture

```
Tailer Interface
├── nxadmTailAdapter (wraps github.com/nxadm/tail)
└── statTail (stat-based implementation)
```

### Interface

```go
type Tailer interface {
    Filename() string
    Lines() <-chan *Line
    Dying() <-chan struct{}
    Err() error
    Stop() error
}
```

## Truncation Detection

The stat-based implementation detects file truncation/rotation by comparing the current file size with the last known size (not offset). This is important for Azure/SMB shares where metadata caching can cause size and offset to differ.

When truncation is detected:
- Position is reset to beginning of file (offset 0)
- New content is read from the beginning
- Works on network shares without inode support

## Large Line Handling

Both implementations handle lines of any size:
- Native tail uses `bufio.Reader.ReadString('\n')`
- Stat-based tail also uses `bufio.Reader.ReadString('\n')` (not `bufio.Scanner`)
- No 64KB line size limitation
- Dynamically grows buffer as needed
- Tested with 128KB+ lines

## Testing

The package includes extensive tests:
- Basic tailing functionality
- Truncation detection (multiple scenarios)
- File deletion handling
- Error propagation
- Poll interval validation
- SeekStart vs SeekEnd behavior

Tests use `ForceRead()` for deterministic, fast execution except for the poll interval test which validates actual timer behavior.

Run tests:
```bash
go test ./pkg/acquisition/modules/file/tailwrapper -v
```

## Usage Example

```go
tailer, err := tailwrapper.TailFile(filename, tailwrapper.Config{
    ReOpen:       true,
    Follow:       true,
    Poll:         false,
    Location:     &tailwrapper.SeekInfo{Offset: 0, Whence: io.SeekEnd},
    TailMode:     "stat",
    PollInterval: 1 * time.Second,  // stat poll interval
})
if err != nil {
    return err
}
defer tailer.Stop()

for line := range tailer.Lines() {
    if line.Err != nil {
        log.Error(line.Err)
        continue
    }
    fmt.Println(line.Text)
}
```

## Benefits

- **Backward compatible**: Default behavior unchanged
- **Flexible**: Easy to switch implementations via configuration
- **Network share friendly**: Stat mode doesn't hold file handles
- **Testable**: Clean interface with mock-friendly design
- **Error recovery**: CrowdSec's existing dead tail recovery works seamlessly

## Implementation Notes

- The stat-based implementation opens the file, reads to EOF, then closes immediately
- Position tracking uses byte count from `scanner.Bytes()` for accuracy
- Channel buffering (100 lines) prevents blocking during burst reads
- Error propagation via tomb.Kill() allows CrowdSec to recover failed tailers

