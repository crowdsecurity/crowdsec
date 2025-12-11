package fileacquisition

import (
	"bufio"
	"cmp"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/nxadm/tail"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/fsutil"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

const defaultPollInterval = 30 * time.Second

func (s *Source) OneShot(ctx context.Context, out chan pipeline.Event) error {
	s.logger.Debug("In oneshot")

	for _, file := range s.files {
		fi, err := os.Stat(file)
		if err != nil {
			return fmt.Errorf("could not stat file %s : %w", file, err)
		}

		if fi.IsDir() {
			s.logger.Warnf("%s is a directory, ignoring it.", file)
			continue
		}

		s.logger.Infof("reading %s at once", file)

		err = s.readFile(ctx, file, out)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Source) StreamingAcquisition(_ context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	s.logger.Debug("Starting live acquisition")
	t.Go(func() error {
		return s.monitorNewFiles(out, t)
	})

	for _, file := range s.files {
		if err := s.setupTailForFile(file, out, true, t); err != nil {
			s.logger.Errorf("Error setting up tail for %s: %s", file, err)
		}
	}

	return nil
}

// checkAndTailFile validates and sets up tailing for a given file. It performs the following checks:
// 1. Verifies if the file exists and is not a directory
// 2. Checks if the filename matches any of the configured patterns
// 3. Sets up file tailing if the file is valid and matches patterns
//
// Parameters:
//   - filename: The path to the file to check and potentially tail
//   - logger: A log.Entry for contextual logging
//   - out: Channel to send file events to
//   - t: A tomb.Tomb for graceful shutdown handling
//
// Returns an error if any validation fails or if tailing setup fails
func (s *Source) checkAndTailFile(filename string, logger *log.Entry, out chan pipeline.Event, t *tomb.Tomb) error {
	// Check if it's a directory
	fi, err := os.Stat(filename)
	if err != nil {
		logger.Errorf("Could not stat() file %s, ignoring it : %s", filename, err)
		return err
	}

	if fi.IsDir() {
		return nil
	}

	logger.Debugf("Processing file %s", filename)

	// Check if file matches any of our patterns
	matched := false

	for _, pattern := range s.config.Filenames {
		logger.Debugf("Matching %s with %s", pattern, filename)

		matched, err = filepath.Match(pattern, filename)
		if err != nil {
			logger.Errorf("Could not match pattern : %s", err)
			continue
		}

		if matched {
			logger.Debugf("Matched %s with %s", pattern, filename)
			break
		}
	}

	if !matched {
		return nil
	}

	// Setup the tail if needed
	if err := s.setupTailForFile(filename, out, false, t); err != nil {
		logger.Errorf("Error setting up tail for file %s: %s", filename, err)
		return err
	}

	return nil
}

func (s *Source) monitorNewFiles(out chan pipeline.Event, t *tomb.Tomb) error {
	logger := s.logger.WithField("goroutine", "inotify")

	// Setup polling if enabled
	var (
		tickerChan <-chan time.Time
		ticker *time.Ticker
	)

	if s.config.DiscoveryPollEnable {
		interval := cmp.Or(s.config.DiscoveryPollInterval, defaultPollInterval)
		logger.Infof("File discovery polling enabled with interval: %s", interval)
		ticker = time.NewTicker(interval)
		tickerChan = ticker.C

		defer ticker.Stop()
	}

	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return nil
			}

			if event.Op&fsnotify.Create != fsnotify.Create {
				continue
			}

			_ = s.checkAndTailFile(event.Name, logger, out, t)

		case <-tickerChan: // Will never trigger if tickerChan is nil
			// Poll for all configured patterns
			for _, pattern := range s.config.Filenames {
				files, err := filepath.Glob(pattern)
				if err != nil {
					logger.Errorf("Error globbing pattern %s during poll: %s", pattern, err)
					continue
				}

				for _, file := range files {
					_ = s.checkAndTailFile(file, logger, out, t)
				}
			}

		case err, ok := <-s.watcher.Errors:
			if !ok {
				return nil
			}

			logger.Errorf("Error while monitoring folder: %s", err)

		case <-t.Dying():
			err := s.watcher.Close()
			if err != nil {
				return fmt.Errorf("could not remove all inotify watches: %w", err)
			}

			return nil
		}
	}
}

func (s *Source) setupTailForFile(file string, out chan pipeline.Event, seekEnd bool, t *tomb.Tomb) error {
	logger := s.logger.WithField("file", file)

	if s.isExcluded(file) {
		return nil
	}

	// Check if we're already tailing
	s.tailMapMutex.RLock()

	if s.tails[file] {
		s.tailMapMutex.RUnlock()
		logger.Debugf("Already tailing file %s, not creating a new tail", file)

		return nil
	}

	s.tailMapMutex.RUnlock()

	// Validate file
	fd, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("unable to read %s : %s", file, err)
	}

	if err = fd.Close(); err != nil {
		return fmt.Errorf("unable to close %s : %s", file, err)
	}

	fi, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("could not stat file %s : %w", file, err)
	}

	if fi.IsDir() {
		logger.Warnf("%s is a directory, ignoring it.", file)
		return nil
	}

	// Determine polling mode
	pollFile := false
	if s.config.PollWithoutInotify != nil {
		pollFile = *s.config.PollWithoutInotify
	} else {
		networkFS, fsType, err := fsutil.IsNetworkFS(file)
		if err != nil {
			logger.Warningf("Could not get fs type for %s : %s", file, err)
		}

		logger.Debugf("fs for %s is network: %t (%s)", file, networkFS, fsType)

		if networkFS {
			logger.Warnf("Disabling inotify polling on %s as it is on a network share. You can manually set poll_without_inotify to true to make this message disappear, or to false to enforce inotify poll", file)

			pollFile = true
		}
	}

	// Check symlink status
	filink, err := os.Lstat(file)
	if err != nil {
		return fmt.Errorf("could not lstat() file %s: %w", file, err)
	}

	if filink.Mode()&os.ModeSymlink == os.ModeSymlink && !pollFile {
		logger.Warnf("File %s is a symlink, but inotify polling is enabled. Crowdsec will not be able to detect rotation. Consider setting poll_without_inotify to true in your configuration", file)
	}

	// Create the tailer with appropriate configuration
	seekInfo := &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd}
	if s.config.Mode == configuration.CAT_MODE {
		seekInfo.Whence = io.SeekStart
	}

	if seekEnd {
		seekInfo.Whence = io.SeekEnd
	}

	logger.Infof("Starting tail (offset: %d, whence: %d)", seekInfo.Offset, seekInfo.Whence)

	tail, err := tail.TailFile(file, tail.Config{
		ReOpen:   true,
		Follow:   true,
		Poll:     pollFile,
		Location: seekInfo,
		Logger:   log.NewEntry(log.StandardLogger()),
	})
	if err != nil {
		return fmt.Errorf("could not start tailing file %s : %w", file, err)
	}

	s.tailMapMutex.Lock()
	s.tails[file] = true
	s.tailMapMutex.Unlock()

	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/tailfile")
		return s.tailFile(out, t, tail)
	})

	return nil
}

func (s *Source) tailFile(out chan pipeline.Event, t *tomb.Tomb, tail *tail.Tail) error {
	logger := s.logger.WithField("tail", tail.Filename)
	logger.Debug("-> start tailing")

	for {
		select {
		case <-t.Dying():
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
			delete(s.tails, tail.Filename)
			s.tailMapMutex.Unlock()

			return nil
		case line := <-tail.Lines:
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

			if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.FileDatasourceLinesRead.With(prometheus.Labels{"source": tail.Filename, "datasource_type": "file", "acquis_type": s.config.Labels["type"]}).Inc()
			}

			src := tail.Filename
			if s.metricsLevel == metrics.AcquisitionMetricsLevelAggregated {
				src = filepath.Base(tail.Filename)
			}

			l := pipeline.Line{
				Raw:     trimLine(line.Text),
				Labels:  s.config.Labels,
				Time:    line.Time,
				Src:     src,
				Process: true,
				Module:  s.GetName(),
			}
			// we're tailing, it must be real time logs
			logger.Debugf("pushing %+v", l)

			evt := pipeline.MakeEvent(s.config.UseTimeMachine, pipeline.LOG, true)
			evt.Line = l

			out <- evt
		}
	}
}

func (s *Source) readFile(ctx context.Context, filename string, out chan pipeline.Event) error {
	var scanner *bufio.Scanner

	logger := s.logger.WithField("oneshot", filename)

	fd, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed opening %s: %w", filename, err)
	}

	defer fd.Close()

	if strings.HasSuffix(filename, ".gz") {
		gz, err := gzip.NewReader(fd)
		if err != nil {
			logger.Errorf("Failed to read gz file: %s", err)
			return fmt.Errorf("failed to read gz %s: %w", filename, err)
		}

		defer gz.Close()

		scanner = bufio.NewScanner(gz)
	} else {
		scanner = bufio.NewScanner(fd)
	}

	scanner.Split(bufio.ScanLines)

	if s.config.MaxBufferSize > 0 {
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, s.config.MaxBufferSize)
	}

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			logger.Info("File datasource stopping")
			return nil
		default:
			if scanner.Text() == "" {
				continue
			}

			l := pipeline.Line{
				Raw:     scanner.Text(),
				Time:    time.Now().UTC(),
				Src:     filename,
				Labels:  s.config.Labels,
				Process: true,
				Module:  s.GetName(),
			}
			logger.Debugf("line %s", l.Raw)
			metrics.FileDatasourceLinesRead.With(prometheus.Labels{"source": filename, "datasource_type": "file", "acquis_type": l.Labels["type"]}).Inc()

			// we're reading logs at once, it must be time-machine buckets
			out <- pipeline.Event{Line: l, Process: true, Type: pipeline.LOG, ExpectMode: pipeline.TIMEMACHINE, Unmarshaled: make(map[string]any)}
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Errorf("Error while reading file: %s", err)
		return err
	}

	return nil
}

// IsTailing returns whether a given file is currently being tailed. For testing purposes.
// It is case sensitive and path delimiter sensitive (filename must match exactly what the filename would look being OS specific)
func (s *Source) IsTailing(filename string) bool {
	s.tailMapMutex.RLock()
	defer s.tailMapMutex.RUnlock()

	return s.tails[filename]
}

// RemoveTail is used for testing to simulate a dead tailer. For testing purposes.
// It is case sensitive and path delimiter sensitive (filename must match exactly what the filename would look being OS specific)
func (s *Source) RemoveTail(filename string) {
	s.tailMapMutex.Lock()
	defer s.tailMapMutex.Unlock()

	delete(s.tails, filename)
}

// isExcluded returns the first matching regexp from the list of excluding patterns,
// or nil if the file is not excluded.
func (s *Source) isExcluded(path string) bool {
	for _, re := range s.exclude_regexps {
		if re.MatchString(path) {
			s.logger.WithField("file", path).Infof("Skipping file: matches exclude regex %q", re)
			return true
		}
	}

	return false
}
