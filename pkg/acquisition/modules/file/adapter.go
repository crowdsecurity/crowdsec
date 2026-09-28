// adapter follows one file with either github.com/nxadm/tail or the in-house tailer.
// nxadm TailFile accepts no context. The in-house TailFile does. The read loop is the same:
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

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file/tail"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// tailedFile is one file followed by nxadm or by the in-house tailer.
// The line channel for the library that was not started stays nil, so that select case never fires.
type tailedFile struct {
	name       string
	dying      <-chan struct{}
	stop       func() error
	tailErr    func() error
	nxadmLines <-chan *nxadmtail.Line
	crowdLines <-chan *tail.Line
}

// newTailedFile starts nxadm for mode tail, and the in-house tailer for crowdtail and crowdtailstat.
// Any other mode that reaches here uses nxadm, matching the historical default.
func newTailedFile(ctx context.Context, filename string, pollFile bool, whence int, mode string, statReadInterval time.Duration) (*tailedFile, error) {
	switch mode {
	case modeCrowdTail:
		return openCrowdTail(ctx, filename, pollFile, whence, true, 0)
	case modeCrowdTailStat:
		return openCrowdTail(ctx, filename, pollFile, whence, false, statReadInterval)
	default:
		return openNxadmTail(filename, pollFile, whence)
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

// openCrowdTail follows filename with the in-house tailer. keepFileOpen selects crowdtail; closing after each read selects crowdtailstat.
func openCrowdTail(ctx context.Context, filename string, pollFile bool, whence int, keepFileOpen bool, statReadInterval time.Duration) (*tailedFile, error) {
	// crowdtail keeps the handle open, so the tailer uses its own tick. crowdtailstat reads on the configured interval.
	var pollInterval time.Duration
	if keepFileOpen {
		pollInterval = 0
	} else {
		pollInterval = statReadInterval
	}

	crowdTail, err := tail.TailFile(ctx, filename, tail.Config{
		ReOpen:       true,
		Poll:         pollFile,
		PollInterval: pollInterval,
		Location:     &tail.SeekInfo{Offset: 0, Whence: whence},
		KeepFileOpen: keepFileOpen,
	})
	if err != nil {
		return nil, err
	}

	return &tailedFile{
		name:       crowdTail.Filename(),
		dying:      crowdTail.Dying(),
		stop:       crowdTail.Stop,
		tailErr:    crowdTail.Err,
		crowdLines: crowdTail.Lines(),
	}, nil
}

// startTailedFile follows file with the tailer selected by the configured mode.
func (s *Source) startTailedFile(ctx context.Context, file string, out chan pipeline.Event, g *errgroup.Group, pollFile bool, whence int) error {
	followed, err := newTailedFile(ctx, file, pollFile, whence, s.config.Mode, s.config.CrowdTailStatModeReadInterval)
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
		// One line from nxadm. The channel is nil when the in-house tailer is running.
		case line := <-followed.nxadmLines:
			var read *tailRead
			if line != nil {
				read = &tailRead{text: line.Text, err: line.Err, time: line.Time}
			}
			if err := s.deliverTailRead(logger, out, followed.name, read); err != nil {
				return err
			}
		// One line from the in-house tailer. The channel is nil when nxadm is running.
		case line := <-followed.crowdLines:
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
