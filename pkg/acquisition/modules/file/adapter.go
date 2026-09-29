// adapter follows one file with either github.com/nxadm/tail or polltail.
// nxadm TailFile accepts no context. polltail TailFile does. The read loop is the same:
// the line channel for the library that was not started stays nil, so that select case never fires.

package fileacquisition

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/go-cs-lib/trace"
	nxadmtail "github.com/nxadm/tail"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file/polltail"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// tailedFile is one file followed by nxadm or by polltail.
// The line channel for the library that was not started stays nil, so that select case never fires.
type tailedFile struct {
	name       string
	dying      <-chan struct{}
	stop       func() error
	tailErr    func() error
	nxadmLines <-chan *nxadmtail.Line
	pollLines  <-chan *polltail.Line
}

// newTailedFile starts nxadm for tail and cat, and polltail for polltail.
func newTailedFile(ctx context.Context, filename string, pollFile bool, whence int, mode string, statReadInterval time.Duration) (*tailedFile, error) {
	switch mode {
	case configuration.TAIL_MODE, configuration.CAT_MODE:
		return openNxadmTail(filename, pollFile, whence)
	case configuration.POLLTAIL_MODE:
		return openPollTail(ctx, filename, whence, statReadInterval)
	default:
		return nil, fmt.Errorf("unsupported mode %q for file source (supported: tail, cat, polltail)", mode)
	}
}

// openNxadmTail follows filename with github.com/nxadm/tail.
func openNxadmTail(filename string, pollFile bool, whence int) (*tailedFile, error) {
	nxadmTail, err := nxadmtail.TailFile(filename, nxadmtail.Config{
		ReOpen:   true,
		Follow:   true,
		Poll:     pollFile,
		Location: &nxadmtail.SeekInfo{Offset: 0, Whence: whence},
		Logger:   log.NewEntry(log.StandardLogger()),
		// Without this, a line read while it is being written is sent incomplete,
		// and the lines written after it can be skipped. Polltail already waits
		// for the newline. https://github.com/crowdsecurity/crowdsec/pull/4678
		// https://github.com/crowdsecurity/crowdsec/issues/2124
		// This also ensures symmetry with polltail.
		CompleteLines: true,
	})
	if err != nil {
		return nil, err
	}

	return &tailedFile{
		name:       nxadmTail.Filename,
		dying:      nxadmTail.Dying(),
		stop:       nxadmTail.Stop,
		tailErr:    nxadmTail.Err,
		nxadmLines: nxadmTail.Lines,
	}, nil
}

// openPollTail follows filename with polltail. Each pass opens the path, reads, and closes it.
func openPollTail(ctx context.Context, filename string, whence int, statReadInterval time.Duration) (*tailedFile, error) {
	pollTail, err := polltail.TailFile(ctx, filename, polltail.Config{
		PollInterval: statReadInterval,
		Location:     &polltail.SeekInfo{Offset: 0, Whence: whence},
	})
	if err != nil {
		return nil, err
	}

	return &tailedFile{
		name:      pollTail.Filename(),
		dying:     pollTail.Dying(),
		stop:      pollTail.Stop,
		tailErr:   pollTail.Err,
		pollLines: pollTail.Lines(),
	}, nil
}

// startTailedFile follows file with the tailer selected by the configured mode.
func (s *Source) startTailedFile(ctx context.Context, file string, out chan pipeline.Event, g *errgroup.Group, pollFile bool, whence int) error {
	followed, err := newTailedFile(ctx, file, pollFile, whence, s.config.Mode, s.config.PollTailReadInterval)
	if err != nil {
		return fmt.Errorf("could not start tailing file %s : %w", file, err)
	}

	s.tailMapMutex.Lock()
	s.tails[file] = true
	s.tailMapMutex.Unlock()

	g.Go(func() error {
		defer trace.ReportPanic()
		return s.readTailedFile(ctx, out, followed)
	})

	return nil
}

// readTailedFile forwards lines until ctx is canceled or the tailer dies.
func (s *Source) readTailedFile(ctx context.Context, out chan pipeline.Event, followed *tailedFile) error {
	logger := s.logger.WithField("tail", followed.name)
	logger.Debug("-> start tailing")

	for {
		select {
		// The acquisition is stopping. Stop the tailer, then leave.
		case <-ctx.Done():
			logger.Info("File datasource stopping")

			if err := followed.stop(); err != nil {
				s.logger.Errorf("error in stop : %s", err)
				return err
			}

			return nil
		// The tailer ended on its own. Drop the path so a recreated file can be tailed again.
		case <-followed.dying:
			readerDied := "file reader died"
			tailErr := followed.tailErr()
			if tailErr != nil {
				readerDied = fmt.Sprintf(readerDied+" : %s", tailErr)
			}

			logger.Warning(readerDied)

			s.tailMapMutex.Lock()
			delete(s.tails, followed.name)
			s.tailMapMutex.Unlock()

			return nil
		// One line from nxadm. The channel is nil when polltail is running.
		case line := <-followed.nxadmLines:
			var read *tailRead
			if line != nil {
				read = &tailRead{text: line.Text, err: line.Err, time: line.Time}
			}
			if err := s.deliverTailRead(logger, out, followed.name, read); err != nil {
				return err
			}
		// One line from polltail. The channel is nil when nxadm is running.
		case line := <-followed.pollLines:
			var read *tailRead
			if line != nil {
				read = &tailRead{text: line.Text, err: line.Err, time: line.Time}
			}
			if err := s.deliverTailRead(logger, out, followed.name, read); err != nil {
				return err
			}
		}
	}
}

// tailRead is one read from either tailer. A nil pointer is an empty read.
type tailRead struct {
	text string
	err  error
	time time.Time
}

// deliverTailRead skips an empty read. A read error stops this file. Otherwise the line is pushed.
func (s *Source) deliverTailRead(logger *log.Entry, out chan pipeline.Event, filename string, read *tailRead) error {
	if read == nil {
		logger.Warning("tail is empty")
		return nil
	}
	if read.err != nil {
		logger.Warningf("fetch error : %v", read.err)
		return read.err
	}
	if read.text == "" {
		return nil
	}

	s.pushTailLine(out, filename, read.text, read.time)
	return nil
}
