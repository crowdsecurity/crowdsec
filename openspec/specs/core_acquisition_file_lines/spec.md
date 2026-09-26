# File acquisition lines

## Purpose
File tailing emits one event per newline-terminated log line. A read that stops before the newline is not a line.

## Requirements

### Requirement: Hold a partial line
The file datasource SHALL NOT emit a tail event for bytes that do not end in a newline. It SHALL keep those bytes in front of the read position and emit them as one line once a newline is written after them. This applies when `tail_mode` is omitted, `default`, or `stat`.

#### Scenario: Fragment then the rest of the line
- **WHEN** the tailer reads `{"a":` and later reads `1}\nthird\n`
- **THEN** the events are `{"a":1}` and `third`

#### Scenario: Truncation drops the fragment
- **WHEN** the tailer has read `{"a":` with no newline and the file is then truncated before `new\n` is written
- **THEN** the only new event is `new`
