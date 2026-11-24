package dockeracquisition

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"
)

// dockerFrames encodes s as stdout frames of at most 16KiB, like the daemon does.
func dockerFrames(s string) string {
	var sb strings.Builder

	for s != "" {
		n := min(len(s), 16*1024)
		sb.Write(binary.BigEndian.AppendUint32([]byte{1, 0, 0, 0}, uint32(n)))
		sb.WriteString(s[:n])
		s = s[n:]
	}

	return sb.String()
}

func dropMsg(size int) string {
	return fmt.Sprintf("dropped a %d bytes log line, larger than max_buffer_size (64)", size)
}

func TestLineScanner(t *testing.T) {
	const maxSize = 64

	long := strings.Repeat("a", 200)

	tests := []struct {
		name      string
		input     string
		tty       bool
		wantLines []string
		wantDrops []string
	}{
		{
			name:      "short lines",
			input:     "foo\nbar\r\nbaz",
			tty:       true,
			wantLines: []string{"foo", "bar", "baz"},
		},
		{
			name:      "line just under the limit",
			input:     strings.Repeat("b", maxSize-1) + "\nnext\n",
			tty:       true,
			wantLines: []string{strings.Repeat("b", maxSize-1), "next"},
		},
		{
			name:      "long line dropped, reading continues",
			input:     "before\n" + long + "\nafter\n",
			tty:       true,
			wantLines: []string{"before", "after"},
			wantDrops: []string{dropMsg(len(long) + 1)},
		},
		{
			name:      "consecutive long lines",
			input:     long + "\n" + long + "\nafter\n",
			tty:       true,
			wantLines: []string{"after"},
			wantDrops: []string{dropMsg(len(long) + 1), dropMsg(len(long) + 1)},
		},
		{
			name:      "long line at EOF without newline",
			input:     "before\n" + long,
			tty:       true,
			wantLines: []string{"before"},
			wantDrops: []string{dropMsg(len(long))},
		},
		{
			name:      "long line split in docker frames",
			input:     dockerFrames("before\n" + long + "\nafter\n"),
			wantLines: []string{"before", "after"},
			wantDrops: []string{dropMsg(len(long) + 1)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger, hook := logtest.NewNullLogger()

			scanner := newLineScanner(strings.NewReader(tc.input), tc.tty, maxSize, log.NewEntry(logger))

			var lines []string
			for scanner.Scan() {
				lines = append(lines, scanner.Text())
			}

			require.NoError(t, scanner.Err())
			require.Equal(t, tc.wantLines, lines)

			var drops []string
			for _, entry := range hook.AllEntries() {
				drops = append(drops, entry.Message)
			}

			require.Equal(t, tc.wantDrops, drops)
		})
	}
}

// Nobody reads the lines once the tail attempt has returned: the reader must not block on send.
func TestReadTailScannerStopsWhenKilled(t *testing.T) {
	scanner := bufio.NewScanner(strings.NewReader("foo\nbar\n"))
	readerTomb := &tomb.Tomb{}
	readerTomb.Go(func() error {
		return ReadTailScanner(scanner, make(chan string), readerTomb)
	})

	readerTomb.Kill(nil)

	done := make(chan error)
	go func() { done <- readerTomb.Wait() }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("reader goroutine still blocked on send")
	}
}
