// Helpers shared by the polltail tests.

package polltail

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// forceReadForTest reads once. The tailer must be in manual mode so the poll loop is not also reading.
func forceReadForTest(fileTailer *PollTail) {
	fileTailer.readLines()
}

// appendToFileInTest opens filename, appends contents, and closes it.
func appendToFileInTest(filename string, contents string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(contents)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

// TailTest is a temp directory the file helpers write into, plus a done channel the line check closes.
type TailTest struct {
	Name string
	path string
	done chan struct{}
	test *testing.T
}

// NewTailTest makes the temp directory the file helpers write into. The test runtime removes that directory.
func NewTailTest(name string, test *testing.T) *TailTest {
	return &TailTest{
		Name: name,
		path: test.TempDir(),
		done: make(chan struct{}),
		test: test,
	}
}

// CreateFile writes contents into name under the temp directory and fails the test on error.
func (tailTest *TailTest) CreateFile(name string, contents string) {
	filePath := filepath.Join(tailTest.path, name)
	if err := os.WriteFile(filePath, []byte(contents), 0o600); err != nil {
		tailTest.test.Fatal(err)
	}
}

// RemoveFile deletes name from the temp directory and fails the test on error.
func (tailTest *TailTest) RemoveFile(name string) {
	filePath := filepath.Join(tailTest.path, name)
	if err := os.Remove(filePath); err != nil {
		tailTest.test.Fatal(err)
	}
}

// RenameFile renames a file inside the temp directory and fails the test on error.
func (tailTest *TailTest) RenameFile(oldname, newname string) {
	oldPath := filepath.Join(tailTest.path, oldname)
	newPath := filepath.Join(tailTest.path, newname)
	if err := os.Rename(oldPath, newPath); err != nil {
		tailTest.test.Fatal(err)
	}
}

// AppendFile adds contents to name in the temp directory and fails the test on error.
func (tailTest *TailTest) AppendFile(name string, contents string) {
	tailTest.writeFile(name, contents, os.O_APPEND|os.O_WRONLY)
}

// TruncateFile replaces name in the temp directory with contents and fails the test on error.
func (tailTest *TailTest) TruncateFile(name string, contents string) {
	tailTest.writeFile(name, contents, os.O_TRUNC|os.O_WRONLY)
}

// writeFile opens name in the temp directory with flag, writes contents, and fails the test on error.
func (tailTest *TailTest) writeFile(name string, contents string, flag int) {
	filePath := filepath.Join(tailTest.path, name)
	file, err := os.OpenFile(filePath, flag, 0o600)
	if err != nil {
		tailTest.test.Fatal(err)
	}
	_, writeErr := file.WriteString(contents)
	closeErr := file.Close()
	if writeErr != nil {
		tailTest.test.Fatal(writeErr)
	}
	if closeErr != nil {
		tailTest.test.Fatal(closeErr)
	}
}

// StartTail follows name in the temp directory with the test context and fails the test if the file cannot be opened.
func (tailTest *TailTest) StartTail(name string, config Config) *PollTail {
	return tailTest.StartTailWithContext(tailTest.test.Context(), name, config)
}

// StartTailWithContext follows name in the temp directory until ctx ends and fails the test if the file cannot be opened.
func (tailTest *TailTest) StartTailWithContext(ctx context.Context, name string, config Config) *PollTail {
	filePath := filepath.Join(tailTest.path, name)
	tail, err := TailFile(ctx, filePath, config)
	if err != nil {
		tailTest.test.Fatal(err)
	}
	return tail
}

// VerifyTailOutput checks lines in order, then closes the helper's done channel. It uses Errorf because callers run it in a goroutine.
func (tailTest *TailTest) VerifyTailOutput(tail *PollTail, lines []string, expectEOF bool) {
	defer close(tailTest.done)
	tailTest.ReadLines(tail, lines)
	if !expectEOF {
		return
	}
	line, ok := <-tail.Lines()
	if !ok || line == nil {
		return
	}
	tailTest.test.Errorf("more content from tail: %+v", line)
}

// ReadLines fails the test with Errorf when a line is missing, unexpected, or late. Callers may run it in a goroutine.
func (tailTest *TailTest) ReadLines(tail *PollTail, lines []string) {
	for _, expectedLine := range lines {
		select {
		case tailedLine, ok := <-tail.Lines():
			if !ok {
				tailTest.reportTailEnded(tail)
				return
			}
			if tailedLine == nil {
				tailTest.test.Errorf("tail.Lines returned nil")
				return
			}
			if tailedLine.Text != expectedLine {
				tailTest.test.Errorf("unexpected line from tail: expecting <<%s>>, got <<%s>>", expectedLine, tailedLine.Text)
				return
			}
		case <-time.After(5 * time.Second):
			tailTest.test.Errorf("timeout waiting for line: %s", expectedLine)
			return
		}
	}
}

// reportTailEnded records whether the channel closed because of a tail error or because lines ran out.
func (tailTest *TailTest) reportTailEnded(tail *PollTail) {
	if err := tail.Err(); err != nil {
		tailTest.test.Errorf("tail ended with error: %v", err)
		return
	}
	tailTest.test.Errorf("tail ended early; expecting more lines")
}

// CollectLines returns non-empty line texts until Lines closes or timeout elapses.
func (*TailTest) CollectLines(tail *PollTail, timeout time.Duration) []string {
	var lines []string
	timer := time.After(timeout)
	for {
		select {
		case line, ok := <-tail.Lines():
			if !ok {
				return lines
			}
			if line == nil || line.Text == "" {
				continue
			}
			lines = append(lines, line.Text)
		case <-timer:
			return lines
		}
	}
}

// waitForLineCheckThenStop waits until VerifyTailOutput closes done, then stops the tailer when stop is set.
func (tailTest *TailTest) waitForLineCheckThenStop(tail *PollTail, stop bool) {
	select {
	case <-tailTest.done:
	case <-time.After(5 * time.Second):
		tailTest.test.Log("Warning: test verification did not complete")
	}
	if err := tail.Stop(); err != nil {
		tailTest.test.Fatal(err)
	}
}

// tailerModes is the single poll mode these tests run. Kept so each test still has the upstream subtest shape.
// we might have more modes in the future, so keeping this for symmetry with upstream.
var tailerModes = []struct {
	name string
}{
	{name: "poll"},
}

// openClosedFileForTest opens filename and closes it, then returns that closed handle so a later seek fails.
func openClosedFileForTest(filename string) (*os.File, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return file, nil
}

// failAfterBytesReaderForTest returns its bytes, then the stored error, including on the read that finishes the bytes.
type failAfterBytesReaderForTest struct {
	data []byte
	err  error
}

// Read copies the remaining bytes. The read that empties them also returns the stored error.
func (reader *failAfterBytesReaderForTest) Read(p []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, reader.err
	}
	copied := copy(p, reader.data)
	reader.data = reader.data[copied:]
	if len(reader.data) == 0 {
		return copied, reader.err
	}
	return copied, nil
}

// readTailLineForTest returns the next line text. It fails the test when the line is missing, nil, or itself an error.
func readTailLineForTest(t *testing.T, tail *PollTail) string {
	t.Helper()

	select {
	case line := <-tail.Lines():
		require.NotNil(t, line)
		require.NoError(t, line.Err)
		return line.Text
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for a line")
		return ""
	}
}

// assertNoTailLineForTest fails the test when a line is already waiting. It does not wait for one to arrive.
func assertNoTailLineForTest(t *testing.T, tail *PollTail) {
	t.Helper()

	select {
	case line := <-tail.Lines():
		text := ""
		if line != nil {
			text = line.Text
		}
		t.Fatalf("unexpected line %q", text)
	default:
	}
}
