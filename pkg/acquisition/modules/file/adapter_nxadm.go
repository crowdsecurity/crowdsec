// adapter_nxadm adapts github.com/nxadm/tail onto the acquisition context.
// TailFile accepts no context, so readAdxmTail calls Stop when ctx is canceled.
// crowdtail and crowdtailstat use adapter_crowdtail.go because that tailer already takes ctx.

package fileacquisition

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/go-cs-lib/trace"
	nxadmtail "github.com/nxadm/tail"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// startAdxmTail follows file with github.com/nxadm/tail. mode tail uses this path.
func (s *Source) startAdxmTail(ctx context.Context, file string, out chan pipeline.Event, g *errgroup.Group, pollFile bool, whence int) error {
	adxmTail, err := nxadmtail.TailFile(file, nxadmtail.Config{
		ReOpen:   true,
		Follow:   true,
		Poll:     pollFile,
		Location: &nxadmtail.SeekInfo{Offset: 0, Whence: whence},
		Logger:   log.NewEntry(log.StandardLogger()),
	})
	if err != nil {
		return fmt.Errorf("could not start tailing file %s : %w", file, err)
	}

	s.tailMapMutex.Lock()
	s.tails[file] = true
	s.tailMapMutex.Unlock()

	g.Go(func() error {
		defer trace.ReportPanic()
		return s.readAdxmTail(ctx, out, adxmTail)
	})

	return nil
}

// readAdxmTail forwards lines from the nxadm tailer until ctx is canceled or the tailer dies.
func (s *Source) readAdxmTail(ctx context.Context, out chan pipeline.Event, adxmTail *nxadmtail.Tail) error {
	logger := s.logger.WithField("tail", adxmTail.Filename)
	logger.Debug("-> start tailing")

	for {
		select {
		// The acquisition is stopping. Stop the tailer, then leave.
		case <-ctx.Done():
			return s.stopTailOnShutdown(logger, adxmTail.Stop)
		// The tailer ended on its own. Drop the path so a recreated file can be tailed again.
		case <-adxmTail.Dying():
			s.dropDeadTail(logger, adxmTail.Filename, adxmTail.Err())
			return nil
		// One line from the tailer. Skip an empty read. A read error stops this file.
		case line := <-adxmTail.Lines:
			var read *tailRead
			if line != nil {
				read = &tailRead{text: line.Text, err: line.Err, time: line.Time}
			}
			if err := s.deliverTailRead(logger, out, adxmTail.Filename, read); err != nil {
				return err
			}
		}
	}
}
