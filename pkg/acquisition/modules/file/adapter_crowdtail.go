// adapter_crowdtail runs mode crowdtail and crowdtailstat on the in-house tailer.
// TailFile already takes ctx, so this file is the matching reader for adapter_nxadm.go.

package fileacquisition

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/file/tail"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// startCrowdTail follows file with the in-house tailer. keepFileOpen selects crowdtail; closing after each read selects crowdtailstat.
func (s *Source) startCrowdTail(ctx context.Context, file string, out chan pipeline.Event, g *errgroup.Group, pollFile bool, whence int, keepFileOpen bool) error {
	// crowdtail keeps the handle open, so the tailer uses its own tick. crowdtailstat reads on the configured interval.
	var pollInterval time.Duration
	if keepFileOpen {
		pollInterval = 0
	} else {
		pollInterval = s.config.CrowdTailStatModeReadInterval
	}

	crowdTail, err := tail.TailFile(ctx, file, tail.Config{
		ReOpen:       true,
		Poll:         pollFile,
		PollInterval: pollInterval,
		Location:     &tail.SeekInfo{Offset: 0, Whence: whence},
		KeepFileOpen: keepFileOpen,
	})
	if err != nil {
		return fmt.Errorf("could not start tailing file %s : %w", file, err)
	}

	s.tailMapMutex.Lock()
	s.tails[file] = true
	s.tailMapMutex.Unlock()

	g.Go(func() error {
		defer trace.ReportPanic()
		return s.readCrowdTail(ctx, out, crowdTail)
	})

	return nil
}

// readCrowdTail forwards lines from the in-house tailer until ctx is canceled or the tailer dies.
func (s *Source) readCrowdTail(ctx context.Context, out chan pipeline.Event, crowdTail *tail.Tailer) error {
	logger := s.logger.WithField("tail", crowdTail.Filename())
	logger.Debug("-> start tailing")

	for {
		select {
		// The acquisition is stopping. Stop the tailer, then leave.
		case <-ctx.Done():
			return s.stopTailOnShutdown(logger, crowdTail.Stop)
		// The tailer ended on its own. Drop the path so a recreated file can be tailed again.
		case <-crowdTail.Dying():
			s.dropDeadTail(logger, crowdTail.Filename(), crowdTail.Err())
			return nil
		// One line from the tailer. Skip an empty read. A read error stops this file.
		case line := <-crowdTail.Lines():
			var read *tailRead
			if line != nil {
				read = &tailRead{text: line.Text, err: line.Err, time: line.Time}
			}
			if err := s.deliverTailRead(logger, out, crowdTail.Filename(), read); err != nil {
				return err
			}
		}
	}
}
