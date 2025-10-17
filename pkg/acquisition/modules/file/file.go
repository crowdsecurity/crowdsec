package fileacquisition

import (
	"bufio"
	"cmp"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	yaml "github.com/goccy/go-yaml"
	"github.com/nxadm/tail"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const defaultPollInterval = 30 * time.Second

type FileConfiguration struct {
	Filenames                         []string
	ExcludeRegexps                    []string `yaml:"exclude_regexps"`
	Filename                          string
	ForceInotify                      bool          `yaml:"force_inotify"`
	MaxBufferSize                     int           `yaml:"max_buffer_size"`
	PollWithoutInotify                *bool         `yaml:"poll_without_inotify"`
	DiscoveryPollEnable               bool          `yaml:"discovery_poll_enable"`
	DiscoveryPollInterval             time.Duration `yaml:"discovery_poll_interval"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type FileSource struct {
	metricsLevel       metrics.AcquisitionMetricsLevel
	config             FileConfiguration
	watcher            *fsnotify.Watcher
	watchedDirectories map[string]bool
	tails              map[string]bool
	logger             *log.Entry
	files              []string
	exclude_regexps    []*regexp.Regexp
	tailMapMutex       *sync.RWMutex
}

func (f *FileSource) GetUuid() string {
	return f.config.UniqueId
}

func (f *FileSource) UnmarshalConfig(yamlConfig []byte) error {
	f.config = FileConfiguration{}

	err := yaml.UnmarshalWithOptions(yamlConfig, &f.config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse FileAcquisition configuration: %s", yaml.FormatError(err, false, false))
	}

	if f.logger != nil {
		f.logger.Tracef("FileAcquisition configuration: %+v", f.config)
	}

	if f.config.Filename != "" {
		f.config.Filenames = append(f.config.Filenames, f.config.Filename)
	}

	if len(f.config.Filenames) == 0 {
		return errors.New("no filename or filenames configuration provided")
	}

	if f.config.Mode == "" {
		f.config.Mode = configuration.TAIL_MODE
	}

	if f.config.Mode != configuration.CAT_MODE && f.config.Mode != configuration.TAIL_MODE {
		return fmt.Errorf("unsupported mode %s for file source", f.config.Mode)
	}

	for _, exclude := range f.config.ExcludeRegexps {
		re, err := regexp.Compile(exclude)
		if err != nil {
			return fmt.Errorf("could not compile regexp %s: %w", exclude, err)
		}

		f.exclude_regexps = append(f.exclude_regexps, re)
	}

	return nil
}

func (f *FileSource) Configure(_ context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	f.logger = logger
	f.metricsLevel = metricsLevel

	err := f.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	f.watchedDirectories = make(map[string]bool)
	f.tailMapMutex = &sync.RWMutex{}
	f.tails = make(map[string]bool)

	f.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("could not create fsnotify watcher: %w", err)
	}

	f.logger.Tracef("Actual FileAcquisition Configuration %+v", f.config)

	for _, pattern := range f.config.Filenames {
		if f.config.ForceInotify {
			directory := filepath.Dir(pattern)
			f.logger.Infof("Force add watch on %s", directory)

			if !f.watchedDirectories[directory] {
				err = f.watcher.Add(directory)
				if err != nil {
					f.logger.Errorf("Could not create watch on directory %s : %s", directory, err)
					continue
				}

				f.watchedDirectories[directory] = true
			}
		}

		files, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("glob failure: %w", err)
		}

		if len(files) == 0 {
			f.logger.Warnf("No matching files for pattern %s", pattern)
			continue
		}

		for _, file := range files {
			if f.isExcluded(file) {
				continue
			}

			if files[0] != pattern && f.config.Mode == configuration.TAIL_MODE { // we have a glob pattern
				directory := filepath.Dir(file)
				f.logger.Debugf("Will add watch to directory: %s", directory)

				if !f.watchedDirectories[directory] {
					err = f.watcher.Add(directory)
					if err != nil {
						f.logger.Errorf("Could not create watch on directory %s : %s", directory, err)
						continue
					}

					f.watchedDirectories[directory] = true
				} else {
					f.logger.Debugf("Watch for directory %s already exists", directory)
				}
			}

			f.logger.Infof("Adding file %s to datasources", file)
			f.files = append(f.files, file)
		}
	}

	return nil
}

func (f *FileSource) ConfigureByDSN(_ context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	if !strings.HasPrefix(dsn, "file://") {
		return fmt.Errorf("invalid DSN %s for file source, must start with file://", dsn)
	}

	f.logger = logger
	f.config = FileConfiguration{}

	dsn = strings.TrimPrefix(dsn, "file://")

	args := strings.Split(dsn, "?")

	if args[0] == "" {
		return errors.New("empty file:// DSN")
	}

	if len(args) == 2 && args[1] != "" {
		params, err := url.ParseQuery(args[1])
		if err != nil {
			return fmt.Errorf("could not parse file args: %w", err)
		}

		for key, value := range params {
			switch key {
			case "log_level":
				if len(value) != 1 {
					return errors.New("expected zero or one value for 'log_level'")
				}

				lvl, err := log.ParseLevel(value[0])
				if err != nil {
					return fmt.Errorf("unknown level %s: %w", value[0], err)
				}

				f.logger.Logger.SetLevel(lvl)
			case "max_buffer_size":
				if len(value) != 1 {
					return errors.New("expected zero or one value for 'max_buffer_size'")
				}

				maxBufferSize, err := strconv.Atoi(value[0])
				if err != nil {
					return fmt.Errorf("could not parse max_buffer_size %s: %w", value[0], err)
				}

				f.config.MaxBufferSize = maxBufferSize
			default:
				return fmt.Errorf("unknown parameter %s", key)
			}
		}
	}

	f.config.Labels = labels
	f.config.Mode = configuration.CAT_MODE
	f.config.UniqueId = uuid

	f.logger.Debugf("Will try pattern %s", args[0])

	files, err := filepath.Glob(args[0])
	if err != nil {
		return fmt.Errorf("glob failure: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no matching files for pattern %s", args[0])
	}

	if len(files) > 1 {
		f.logger.Infof("Will read %d files", len(files))
	}

	for _, file := range files {
		f.logger.Infof("Adding file %s to filelist", file)
		f.files = append(f.files, file)
	}

	return nil
}

func (f *FileSource) GetMode() string {
	return f.config.Mode
}

// SupportedModes returns the supported modes by the acquisition module
func (f *FileSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}

// OneShotAcquisition reads a set of file and returns when done
func (f *FileSource) OneShotAcquisition(_ context.Context, out chan types.Event, t *tomb.Tomb) error {
	f.logger.Debug("In oneshot")

	for _, file := range f.files {
		fi, err := os.Stat(file)
		if err != nil {
			return fmt.Errorf("could not stat file %s : %w", file, err)
		}

		if fi.IsDir() {
			f.logger.Warnf("%s is a directory, ignoring it.", file)
			continue
		}

		f.logger.Infof("reading %s at once", file)

		err = f.readFile(file, out, t)
		if err != nil {
			return err
		}
	}

	return nil
}

func (f *FileSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.FileDatasourceLinesRead}
}

func (f *FileSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.FileDatasourceLinesRead}
}

func (f *FileSource) GetName() string {
	return "file"
}

func (f *FileSource) CanRun() error {
	return nil
}

func (f *FileSource) StreamingAcquisition(_ context.Context, out chan types.Event, t *tomb.Tomb) error {
	f.logger.Debug("Starting live acquisition")
	t.Go(func() error {
		return f.monitorNewFiles(out, t)
	})

	for _, file := range f.files {
		if err := f.setupTailForFile(file, out, true, t); err != nil {
			f.logger.Errorf("Error setting up tail for %s: %s", file, err)
		}
	}

	return nil
}

func (f *FileSource) Dump() any {
	return f
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
func (f *FileSource) checkAndTailFile(filename string, logger *log.Entry, out chan types.Event, t *tomb.Tomb) error {
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
	for _, pattern := range f.config.Filenames {
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
	if err := f.setupTailForFile(filename, out, false, t); err != nil {
		logger.Errorf("Error setting up tail for file %s: %s", filename, err)
		return err
	}

	return nil
}

func (f *FileSource) monitorNewFiles(out chan types.Event, t *tomb.Tomb) error {
	logger := f.logger.WithField("goroutine", "inotify")

	// Setup polling if enabled
	var tickerChan <-chan time.Time
	var ticker *time.Ticker
	if f.config.DiscoveryPollEnable {
		interval := cmp.Or(f.config.DiscoveryPollInterval, defaultPollInterval)
		logger.Infof("File discovery polling enabled with interval: %s", interval)
		ticker = time.NewTicker(interval)
		tickerChan = ticker.C
		defer ticker.Stop()
	}

	for {
		select {
		case event, ok := <-f.watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&fsnotify.Create != fsnotify.Create {
				continue
			}
			_ = f.checkAndTailFile(event.Name, logger, out, t)

		case <-tickerChan: // Will never trigger if tickerChan is nil
			// Poll for all configured patterns
			for _, pattern := range f.config.Filenames {
				files, err := filepath.Glob(pattern)
				if err != nil {
					logger.Errorf("Error globbing pattern %s during poll: %s", pattern, err)
					continue
				}
				for _, file := range files {
					_ = f.checkAndTailFile(file, logger, out, t)
				}
			}

		case err, ok := <-f.watcher.Errors:
			if !ok {
				return nil
			}
			logger.Errorf("Error while monitoring folder: %s", err)

		case <-t.Dying():
			err := f.watcher.Close()
			if err != nil {
				return fmt.Errorf("could not remove all inotify watches: %w", err)
			}
			return nil
		}
	}
}

func (f *FileSource) setupTailForFile(file string, out chan types.Event, seekEnd bool, t *tomb.Tomb) error {
	logger := f.logger.WithField("file", file)

	if f.isExcluded(file) {
		return nil
	}

	// Check if we're already tailing
	f.tailMapMutex.RLock()
	if f.tails[file] {
		f.tailMapMutex.RUnlock()
		logger.Debugf("Already tailing file %s, not creating a new tail", file)
		return nil
	}
	f.tailMapMutex.RUnlock()

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
	if f.config.PollWithoutInotify != nil {
		pollFile = *f.config.PollWithoutInotify
	} else {
		networkFS, fsType, err := types.IsNetworkFS(file)
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
	if f.config.Mode == configuration.CAT_MODE {
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

	f.tailMapMutex.Lock()
	f.tails[file] = true
	f.tailMapMutex.Unlock()

	t.Go(func() error {
		defer trace.CatchPanic("crowdsec/acquis/tailfile")
		return f.tailFile(out, t, tail)
	})

	return nil
}

func (f *FileSource) tailFile(out chan types.Event, t *tomb.Tomb, tail *tail.Tail) error {
	logger := f.logger.WithField("tail", tail.Filename)
	logger.Debug("-> start tailing")

	for {
		select {
		case <-t.Dying():
			logger.Info("File datasource stopping")

			if err := tail.Stop(); err != nil {
				f.logger.Errorf("error in stop : %s", err)
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
			f.tailMapMutex.Lock()
			delete(f.tails, tail.Filename)
			f.tailMapMutex.Unlock()

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

			if f.metricsLevel != metrics.AcquisitionMetricsLevelNone {
				metrics.FileDatasourceLinesRead.With(prometheus.Labels{"source": tail.Filename, "datasource_type": "file", "acquis_type": f.config.Labels["type"]}).Inc()
			}

			src := tail.Filename
			if f.metricsLevel == metrics.AcquisitionMetricsLevelAggregated {
				src = filepath.Base(tail.Filename)
			}

			l := types.Line{
				Raw:     trimLine(line.Text),
				Labels:  f.config.Labels,
				Time:    line.Time,
				Src:     src,
				Process: true,
				Module:  f.GetName(),
			}
			// we're tailing, it must be real time logs
			logger.Debugf("pushing %+v", l)

			evt := types.MakeEvent(f.config.UseTimeMachine, types.LOG, true)
			evt.Line = l
			out <- evt
		}
	}
}

func (f *FileSource) readFile(filename string, out chan types.Event, t *tomb.Tomb) error {
	var scanner *bufio.Scanner

	logger := f.logger.WithField("oneshot", filename)

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

	if f.config.MaxBufferSize > 0 {
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, f.config.MaxBufferSize)
	}

	for scanner.Scan() {
		select {
		case <-t.Dying():
			logger.Info("File datasource stopping")
			return nil
		default:
			if scanner.Text() == "" {
				continue
			}

			l := types.Line{
				Raw:     scanner.Text(),
				Time:    time.Now().UTC(),
				Src:     filename,
				Labels:  f.config.Labels,
				Process: true,
				Module:  f.GetName(),
			}
			logger.Debugf("line %s", l.Raw)
			metrics.FileDatasourceLinesRead.With(prometheus.Labels{"source": filename, "datasource_type": "file", "acquis_type": l.Labels["type"]}).Inc()

			// we're reading logs at once, it must be time-machine buckets
			out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: types.TIMEMACHINE, Unmarshaled: make(map[string]any)}
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Errorf("Error while reading file: %s", err)
		t.Kill(err)

		return err
	}

	t.Kill(nil)

	return nil
}

// IsTailing returns whether a given file is currently being tailed. For testing purposes.
// It is case sensitive and path delimiter sensitive (filename must match exactly what the filename would look being OS specific)
func (f *FileSource) IsTailing(filename string) bool {
	f.tailMapMutex.RLock()
	defer f.tailMapMutex.RUnlock()
	return f.tails[filename]
}

// RemoveTail is used for testing to simulate a dead tailer. For testing purposes.
// It is case sensitive and path delimiter sensitive (filename must match exactly what the filename would look being OS specific)
func (f *FileSource) RemoveTail(filename string) {
	f.tailMapMutex.Lock()
	defer f.tailMapMutex.Unlock()
	delete(f.tails, filename)
}

// isExcluded returns the first matching regexp from the list of excluding patterns,
// or nil if the file is not excluded.
func (f *FileSource) isExcluded(path string) bool {
	for _, re := range f.exclude_regexps {
		if re.MatchString(path) {
			f.logger.WithField("file", path).Infof("Skipping file: matches exclude regex %q", re)
			return true
		}
	}
	return false
}
