package fileacquisition

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/fsnotify/fsnotify"
	"github.com/nxadm/tail"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

var linesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_filesource_hits_total",
		Help: "Total lines that were read.",
	},
	[]string{"source"})

type FileConfiguration struct {
	Filenames                         []string
	Filename                          string
	ForceInotify                      bool `yaml:"force_inotify"`
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type FileSource struct {
	config             FileConfiguration
	watcher            *fsnotify.Watcher
	watchedDirectories map[string]bool
	tails              map[string]bool
	logger             *log.Entry
	files              []string
}

func (f *FileSource) Configure(Config []byte, logger *log.Entry) error {
	fileConfig := FileConfiguration{}
	f.logger = logger
	f.watchedDirectories = make(map[string]bool)
	f.tails = make(map[string]bool)
	err := yaml.UnmarshalStrict(Config, &fileConfig)
	if err != nil {
		return errors.Wrap(err, "Cannot parse FileAcquisition configuration")
	}
	f.logger.Tracef("FileAcquisition configuration: %+v", fileConfig)
	if len(fileConfig.Filename) != 0 {
		fileConfig.Filenames = append(fileConfig.Filenames, fileConfig.Filename)
	}
	if len(fileConfig.Filenames) == 0 {
		return fmt.Errorf("no filename or filenames configuration provided")
	}
	f.config = fileConfig
	if f.config.Mode == "" {
		f.config.Mode = configuration.TAIL_MODE
	}
	if f.config.Mode != configuration.CAT_MODE && f.config.Mode != configuration.TAIL_MODE {
		return fmt.Errorf("unsupported mode %s for file source", f.config.Mode)
	}
	f.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return errors.Wrapf(err, "Could not create fsnotify watcher")
	}
	f.logger.Tracef("Actual FileAcquisition Configuration %+v", f.config)
	for _, pattern := range f.config.Filenames {
		if f.config.ForceInotify {
			directory := path.Dir(pattern)
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
			return errors.Wrap(err, "Glob failure")
		}
		if len(files) == 0 {
			f.logger.Warnf("No matching files for pattern %s", pattern)
			continue
		}
		for _, file := range files {
			if files[0] != pattern && f.config.Mode == configuration.TAIL_MODE { //we have a glob pattern
				directory := path.Dir(file)
				if !f.watchedDirectories[directory] {

					err = f.watcher.Add(directory)
					if err != nil {
						f.logger.Errorf("Could not create watch on directory %s : %s", directory, err)
						continue
					}
					f.watchedDirectories[directory] = true
				}
			}
			f.logger.Infof("Adding file %s to datasources", file)
			f.files = append(f.files, file)
		}
	}
	return nil
}

func (f *FileSource) ConfigureByDSN(dsn string, labels map[string]string, logger *log.Entry) error {
	if !strings.HasPrefix(dsn, "file://") {
		return fmt.Errorf("invalid DSN %s for file source, must start with file://", dsn)
	}

	f.logger = logger

	dsn = strings.TrimPrefix(dsn, "file://")

	args := strings.Split(dsn, "?")

	if len(args[0]) == 0 {
		return fmt.Errorf("empty file:// DSN")
	}

	if len(args) == 2 && len(args[1]) != 0 {
		params, err := url.ParseQuery(args[1])
		if err != nil {
			return fmt.Errorf("could not parse file args : %s", err)
		}
		for key, value := range params {
			if key != "log_level" {
				return fmt.Errorf("unsupported key %s in file DSN", key)
			}
			if len(value) != 1 {
				return fmt.Errorf("expected zero or one value for 'log_level'")
			}
			lvl, err := log.ParseLevel(value[0])
			if err != nil {
				return errors.Wrapf(err, "unknown level %s", value[0])
			}
			f.logger.Logger.SetLevel(lvl)
		}
	}

	f.config = FileConfiguration{}
	f.config.Labels = labels
	f.config.Mode = configuration.CAT_MODE

	f.logger.Debugf("Will try pattern %s", args[0])
	files, err := filepath.Glob(args[0])
	if err != nil {
		return errors.Wrap(err, "Glob failure")
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

//SupportedModes returns the supported modes by the acquisition module
func (f *FileSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}

//OneShotAcquisition reads a set of file and returns when done
func (f *FileSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
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
	return []prometheus.Collector{linesRead}
}

func (f *FileSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{linesRead}
}

func (f *FileSource) GetName() string {
	return "file"
}

func (f *FileSource) CanRun() error {
	return nil
}

func (f *FileSource) StreamingAcquisition(out chan types.Event, t *tomb.Tomb) error {
	f.logger.Debug("Starting live acquisition")
	t.Go(func() error {
		return f.monitorNewFiles(out, t)
	})
	for _, file := range f.files {
		//cf. https://github.com/crowdsecurity/crowdsec/issues/1168
		//do not rely on stat, reclose file immediately as it's opened by Tail
		fd, err := os.Open(file)
		if err != nil {
			f.logger.Errorf("unable to read %s : %s", file, err)
			continue
		}
		if err := fd.Close(); err != nil {
			f.logger.Errorf("unable to close %s : %s", file, err)
			continue
		}

		fi, err := os.Stat(file)
		if err != nil {
			return fmt.Errorf("could not stat file %s : %w", file, err)
		}
		if fi.IsDir() {
			f.logger.Warnf("%s is a directory, ignoring it.", file)
			continue
		}
		tail, err := tail.TailFile(file, tail.Config{ReOpen: true, Follow: true, Poll: true, Location: &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd}})
		if err != nil {
			f.logger.Errorf("Could not start tailing file %s : %s", file, err)
			continue
		}
		f.tails[file] = true
		t.Go(func() error {
			defer types.CatchPanic("crowdsec/acquis/file/live/fsnotify")
			return f.tailFile(out, t, tail)
		})
	}
	return nil
}

func (f *FileSource) Dump() interface{} {
	return f
}

func (f *FileSource) monitorNewFiles(out chan types.Event, t *tomb.Tomb) error {
	logger := f.logger.WithField("goroutine", "inotify")
	for {
		select {
		case event, ok := <-f.watcher.Events:
			if !ok {
				return nil
			}

			if event.Op&fsnotify.Create == fsnotify.Create {
				fi, err := os.Stat(event.Name)
				if err != nil {
					logger.Errorf("Could not stat() new file %s, ignoring it : %s", event.Name, err)
					continue
				}
				if fi.IsDir() {
					continue
				}
				logger.Debugf("Detected new file %s", event.Name)
				matched := false
				for _, pattern := range f.config.Filenames {
					logger.Debugf("Matching %s with %s", pattern, event.Name)
					matched, err = path.Match(pattern, event.Name)
					if err != nil {
						logger.Errorf("Could not match pattern : %s", err)
						continue
					}
					if matched {
						break
					}
				}
				if !matched {
					continue
				}
				if f.tails[event.Name] {
					//we already have a tail on it, do not start a new one
					logger.Debugf("Already tailing file %s, not creating a new tail", event.Name)
					break
				}
				//cf. https://github.com/crowdsecurity/crowdsec/issues/1168
				//do not rely on stat, reclose file immediately as it's opened by Tail
				fd, err := os.Open(event.Name)
				if err != nil {
					f.logger.Errorf("unable to read %s : %s", event.Name, err)
					continue
				}
				if err := fd.Close(); err != nil {
					f.logger.Errorf("unable to close %s : %s", event.Name, err)
					continue
				}
				//Slightly different parameters for Location, as we want to read the first lines of the newly created file
				tail, err := tail.TailFile(event.Name, tail.Config{ReOpen: true, Follow: true, Poll: true, Location: &tail.SeekInfo{Offset: 0, Whence: io.SeekStart}})
				if err != nil {
					logger.Errorf("Could not start tailing file %s : %s", event.Name, err)
					break
				}
				f.tails[event.Name] = true
				t.Go(func() error {
					defer types.CatchPanic("crowdsec/acquis/tailfile")
					return f.tailFile(out, t, tail)
				})
			}
		case err, ok := <-f.watcher.Errors:
			if !ok {
				return nil
			}
			logger.Errorf("Error while monitoring folder: %s", err)
		case <-t.Dying():
			err := f.watcher.Close()
			if err != nil {
				return errors.Wrapf(err, "could not remove all inotify watches")
			}
			return nil
		}
	}
}

func (f *FileSource) tailFile(out chan types.Event, t *tomb.Tomb, tail *tail.Tail) error {
	logger := f.logger.WithField("tail", tail.Filename)
	logger.Debugf("-> Starting tail of %s", tail.Filename)
	for {
		l := types.Line{}
		select {
		case <-t.Dying():
			logger.Infof("File datasource %s stopping", tail.Filename)
			if err := tail.Stop(); err != nil {
				f.logger.Errorf("error in stop : %s", err)
				return err
			}
			return nil
		case <-tail.Tomb.Dying(): //our tailer is dying
			logger.Warningf("File reader of %s died", tail.Filename)
			t.Kill(fmt.Errorf("dead reader for %s", tail.Filename))
			return fmt.Errorf("reader for %s is dead", tail.Filename)
		case line := <-tail.Lines:
			if line == nil {
				logger.Debugf("Nil line")
				return fmt.Errorf("tail for %s is empty", tail.Filename)
			}
			if line.Err != nil {
				logger.Warningf("fetch error : %v", line.Err)
				return line.Err
			}
			if line.Text == "" { //skip empty lines
				continue
			}
			linesRead.With(prometheus.Labels{"source": tail.Filename}).Inc()
			l.Raw = line.Text
			l.Labels = f.config.Labels
			l.Time = line.Time
			l.Src = tail.Filename
			l.Process = true
			l.Module = f.GetName()
			//we're tailing, it must be real time logs
			logger.Debugf("pushing %+v", l)
			out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
		}
	}
}

func (f *FileSource) readFile(filename string, out chan types.Event, t *tomb.Tomb) error {
	var scanner *bufio.Scanner
	logger := f.logger.WithField("oneshot", filename)
	fd, err := os.Open(filename)

	if err != nil {
		return errors.Wrapf(err, "failed opening %s", filename)
	}
	defer fd.Close()

	if strings.HasSuffix(filename, ".gz") {
		gz, err := gzip.NewReader(fd)
		if err != nil {
			logger.Errorf("Failed to read gz file: %s", err)
			return errors.Wrapf(err, "failed to read gz %s", filename)
		}
		defer gz.Close()
		scanner = bufio.NewScanner(gz)

	} else {
		scanner = bufio.NewScanner(fd)
	}
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		logger.Debugf("line %s", scanner.Text())
		l := types.Line{}
		l.Raw = scanner.Text()
		l.Time = time.Now()
		l.Src = filename
		l.Labels = f.config.Labels
		l.Process = true
		l.Module = f.GetName()
		linesRead.With(prometheus.Labels{"source": filename}).Inc()

		//we're reading logs at once, it must be time-machine buckets
		out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.TIMEMACHINE}
	}
	t.Kill(nil)
	return nil
}
