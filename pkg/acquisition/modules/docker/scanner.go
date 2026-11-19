package dockeracquisition

import (
	"bufio"
	"bytes"
	"io"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/dlog"
)

// newLineScanner reads lines from a docker log stream. Lines of maxSize bytes or more are
// dropped with a warning: a bufio.Scanner cannot recover from ErrTooLong, so failing would
// kill the stream on every long line.
func newLineScanner(r io.Reader, tty bool, maxSize int, logger *log.Entry) *bufio.Scanner {
	if !tty {
		// normalize docker API logs (cf. https://ahmet.im/blog/docker-logs-api-binary-format-explained/)
		r = dlog.NewReader(r)
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, maxSize)

	dropped := 0 // bytes of the current overlong line discarded so far

	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if dropped == 0 {
			// the buffer can't grow anymore and holds no full line
			if len(data) >= maxSize && bytes.IndexByte(data, '\n') < 0 {
				dropped = len(data)
				return len(data), nil, nil
			}

			return bufio.ScanLines(data, atEOF)
		}

		i := bytes.IndexByte(data, '\n')
		if i < 0 && !atEOF {
			dropped += len(data)
			return len(data), nil, nil
		}

		end := len(data)
		if i >= 0 {
			end = i + 1
		}

		logger.Warnf("dropped a %d bytes log line, larger than max_buffer_size (%d)", dropped+end, maxSize)

		dropped = 0

		// Scan() reads again after a nil token instead of splitting what's left, which would
		// hold the next line back until more data comes in.
		advance, token, err := bufio.ScanLines(data[end:], atEOF)

		return end + advance, token, err
	})

	return scanner
}
