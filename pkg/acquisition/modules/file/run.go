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
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

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

// Stream tails configured files and emits line events until ctx is canceled.
func (s *Source) Stream(ctx context.Context, out chan pipeline.Event) error {
	s.logger.Debug("Starting live acquisition")

	g, ctx := errgroup.WithContext(ctx)

	// Start file monitoring goroutine
	g.Go(func() error {
		defer trace.ReportPanic()
		return s.monitorNewFiles(ctx, out, g)
	})

	// Start tailing existing files
	for _, file := range s.files {
		if err := s.setupTailForFile(ctx, file, out, true, g); err != nil {
			s.logger.Errorf("Error setting up tail for %s: %s", file, err)
		}
	}

	// Block until all goroutines complete or context is canceled
	return g.Wait()
}

// checkAndTailFile validates and sets up tailing for a given file. It performs the following checks:
// 1. Verifies if the file exists and is not a directory
// 2. Checks if the filename matches any of the configured patterns
// 3. Sets up file tailing if the file is valid and matches patterns
//
// Parameters:
//   - ctx: Context for cancellation
//   - filename: The path to the file to check and potentially tail
//   - logger: A log.Entry for contextual logging
//   - out: Channel to send file events to
//   - g: An errgroup.Group for goroutine management
//
// Returns an error if any validation fails or if tailing setup fails
func (s *Source) checkAndTailFile(ctx context.Context, filename string, logger *log.Entry, out chan pipeline.Event, g *errgroup.Group) error {
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
	if err := s.setupTailForFile(ctx, filename, out, false, g); err != nil {
		logger.Errorf("Error setting up tail for file %s: %s", filename, err)
		return err
	}

	return nil
}

func (s *Source) monitorNewFiles(ctx context.Context, out chan pipeline.Event, g *errgroup.Group) error {
	logger := s.logger.WithField("goroutine", "inotify")

	// Setup polling if enabled
	var (
		tickerChan <-chan time.Time
		ticker     *time.Ticker
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

			_ = s.checkAndTailFile(ctx, event.Name, logger, out, g)

		case <-tickerChan: // Will never trigger if tickerChan is nil
			// Poll for all configured patterns
			for _, pattern := range s.config.Filenames {
				files, err := filepath.Glob(pattern)
				if err != nil {
					logger.Errorf("Error globbing pattern %s during poll: %s", pattern, err)
					continue
				}

				for _, file := range files {
					_ = s.checkAndTailFile(ctx, file, logger, out, g)
				}
			}

		case err, ok := <-s.watcher.Errors:
			if !ok {
				return nil
			}

			logger.Errorf("Error while monitoring folder: %s", err)

		case <-ctx.Done():
			err := s.watcher.Close()
			if err != nil {
				return fmt.Errorf("could not remove all inotify watches: %w", err)
			}

			return nil
		}
	}
}

func (s *Source) setupTailForFile(ctx context.Context, file string, out chan pipeline.Event, seekEnd bool, g *errgroup.Group) error {
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

	// Where following starts. seekEnd wins over cat mode, matching the historical nxadm setup.
	whence := io.SeekEnd
	if s.config.Mode == configuration.CAT_MODE && !seekEnd {
		whence = io.SeekStart
	}

	logger.Infof("Starting tail (offset: %d, whence: %d)", 0, whence)

	return s.startTailedFile(ctx, file, out, g, pollFile, whence)
}

// pushTailLine records one tailed line and sends it on the shared acquisition channel.
func (s *Source) pushTailLine(out chan pipeline.Event, filename string, text string, lineTime time.Time) {
	if s.metricsLevel != metrics.AcquisitionMetricsLevelNone {
		metrics.FileDatasourceLinesRead.With(prometheus.Labels{"source": filename, "datasource_type": ModuleName, "acquis_type": s.config.Labels["type"]}).Inc()
	}

	src := filename
	if s.metricsLevel == metrics.AcquisitionMetricsLevelAggregated {
		src = filepath.Base(filename)
	}

	line := pipeline.Line{
		Raw:     trimLine(text),
		Labels:  s.config.Labels,
		Time:    lineTime,
		Src:     src,
		Process: true,
		Module:  s.GetName(),
	}
	s.logger.WithField("tail", filename).Debugf("pushing %+v", line)

	evt := pipeline.MakeEvent(s.config.UseTimeMachine, pipeline.LOG, true)
	evt.Line = line
	out <- evt
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
			metrics.FileDatasourceLinesRead.With(prometheus.Labels{"source": filename, "datasource_type": ModuleName, "acquis_type": l.Labels["type"]}).Inc()

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
