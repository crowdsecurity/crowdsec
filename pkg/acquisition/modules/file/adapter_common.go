// adapter_common is the reader behavior shared by adapter_nxadm.go and adapter_crowdtail.go.
// The two tailers do not share a type, so each reader converts its own line and calls these methods.

package fileacquisition

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// stopTailOnShutdown stops the tailer because the acquisition context was canceled.
func (s *Source) stopTailOnShutdown(logger *log.Entry, stop func() error) error {
	logger.Info("File datasource stopping")

	if err := stop(); err != nil {
		s.logger.Errorf("error in stop : %s", err)
		return err
	}

	return nil
}

// dropDeadTail logs why the tailer ended and removes the path so a recreated file can be tailed again.
func (s *Source) dropDeadTail(logger *log.Entry, filename string, tailErr error) {
	readerDied := "file reader died"
	if tailErr != nil {
		readerDied = fmt.Sprintf(readerDied+" : %s", tailErr)
	}

	logger.Warning(readerDied)

	s.tailMapMutex.Lock()
	delete(s.tails, filename)
	s.tailMapMutex.Unlock()
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
