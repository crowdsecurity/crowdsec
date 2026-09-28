// adapter_nxadm adapts github.com/nxadm/tail onto the acquisition context.
// TailFile accepts no context, so readLibraryTail calls Stop when ctx is canceled.
// tail2 and tail2stat use adapter_tail2.go because that tailer already takes ctx.

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

// startLibraryTail follows file with github.com/nxadm/tail. mode tail uses this path.
func (s *Source) startLibraryTail(ctx context.Context, file string, out chan pipeline.Event, g *errgroup.Group, pollFile bool, whence int) error {
	libraryTail, err := nxadmtail.TailFile(file, nxadmtail.Config{
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
		return s.readLibraryTail(ctx, out, libraryTail)
	})

	return nil
}

// readLibraryTail forwards lines from the nxadm tailer until ctx is canceled or the tailer dies.
func (s *Source) readLibraryTail(ctx context.Context, out chan pipeline.Event, libraryTail *nxadmtail.Tail) error {
	logger := s.logger.WithField("tail", libraryTail.Filename)
	logger.Debug("-> start tailing")

	for {
		select {
		case <-ctx.Done():
			logger.Info("File datasource stopping")

			if err := libraryTail.Stop(); err != nil {
				s.logger.Errorf("error in stop : %s", err)
				return err
			}

			return nil
		case <-libraryTail.Dying():
			errMsg := "file reader died"

			err := libraryTail.Err()
			if err != nil {
				errMsg = fmt.Sprintf(errMsg+" : %s", err)
			}

			logger.Warning(errMsg)

			s.tailMapMutex.Lock()
			delete(s.tails, libraryTail.Filename)
			s.tailMapMutex.Unlock()

			return nil
		case line := <-libraryTail.Lines:
			if line == nil {
				logger.Warning("tail is empty")
				continue
			}

			if line.Err != nil {
				logger.Warningf("fetch error : %v", line.Err)
				return line.Err
			}

			if line.Text == "" {
				continue
			}

			s.pushTailLine(out, libraryTail.Filename, line.Text, line.Time)
		}
	}
}
