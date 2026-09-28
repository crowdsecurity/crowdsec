// adapter_tail2 runs mode tail2 and tail2stat on the in-house tailer.
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

// startInHouseTail follows file with the in-house tailer. keepFileOpen selects tail2; closing after each read selects tail2stat.
func (s *Source) startInHouseTail(ctx context.Context, file string, out chan pipeline.Event, g *errgroup.Group, pollFile bool, whence int, keepFileOpen bool) error {
	pollInterval := time.Duration(0)
	if !keepFileOpen {
		pollInterval = s.config.Tail2StatReadInterval
	}

	inHouseTail, err := tail.TailFile(ctx, file, tail.Config{
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
		return s.tailFile(ctx, out, inHouseTail)
	})

	return nil
}

// tailFile forwards lines from the in-house tailer until ctx is canceled or the tailer dies.
func (s *Source) tailFile(ctx context.Context, out chan pipeline.Event, tail tail.Tailer) error {
	logger := s.logger.WithField("tail", tail.Filename())
	logger.Debug("-> start tailing")

	for {
		select {
		case <-ctx.Done():
			logger.Info("File datasource stopping")

			if err := tail.Stop(); err != nil {
				s.logger.Errorf("error in stop : %s", err)
				return err
			}

			return nil
		case <-tail.Dying(): // our tailer is dying
			errMsg := "file reader died"

			err := tail.Err()
			if err != nil {
				errMsg = fmt.Sprintf(errMsg+" : %s", err)
			}

			logger.Warning(errMsg)

			// Just remove the dead tailer from our map and return
			// monitorNewFiles will pick up the file again if it's recreated
			s.tailMapMutex.Lock()
			delete(s.tails, tail.Filename())
			s.tailMapMutex.Unlock()

			return nil
		case line := <-tail.Lines():
			if line == nil {
				logger.Warning("tail is empty")
				continue
			}

			if line.Err != nil {
				logger.Warningf("fetch error : %v", line.Err)
				return line.Err
			}

			if line.Text == "" { // skip empty lines
				continue
			}

			s.pushTailLine(out, tail.Filename(), line.Text, line.Time)
		}
	}
}
