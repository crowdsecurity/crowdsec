package file_acquisition

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
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

func (f *FileSource) SupportedDSN() []string {
	return []string{"file://"}
}

func (f *FileSource) Configure(Config []byte, logger *log.Entry) error {
	f.config.SetDefaults()
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
			f.logger.Infof("No matching files for pattern %s", pattern)
			continue
		}
		f.logger.Infof("Will read %d files", len(files))
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
			f.logger.Infof("Adding file %s to filelist", file)
			f.files = append(f.files, file)
		}
	}
	return nil
}

func (f *FileSource) ConfigureByDSN(dsn string, logger *log.Entry) error {
	if !strings.HasPrefix(dsn, "file://") {
		return fmt.Errorf("invalid DSN %s for file source, must start with file://", dsn)
	}
	pattern := strings.TrimPrefix(dsn, "file://")
	if len(pattern) == 0 {
		return fmt.Errorf("empty file:// DSN")
	}
	f.logger = logger
	files, err := filepath.Glob(pattern)
	if err != nil {
		return errors.Wrap(err, "Glob failure")
	}
	if len(files) == 0 {
		return fmt.Errorf("no matching files for pattern %s", pattern)
	}
	f.logger.Infof("Will read %d files", len(files))
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
	return nil
}

func (f *FileSource) CanRun() error {
	return nil
}

func (f *FileSource) LiveAcquisition(out chan types.Event, t *tomb.Tomb) error {
	f.logger.Debugf("Starting live acquisition")
	t.Go(func() error {
		return f.monitorNewFiles(out, t)
	})
	for _, file := range f.files {
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
	for {
		select {
		case event, ok := <-f.watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&fsnotify.Create == fsnotify.Create {
				fi, err := os.Stat(event.Name)
				if err != nil {
					f.logger.Errorf("Could not stat() new file %s, ignoring it : %s", event.Name, err)
				}
				if fi.IsDir() {
					continue
				}
				f.logger.Infof("Detected new file %s", event.Name)
				matched := false
				for _, pattern := range f.config.Filenames {
					f.logger.Debugf("Matching %s with %s", pattern, event.Name)
					matched, err = path.Match(pattern, event.Name)
					if err != nil {
						f.logger.Errorf("Could not match pattern : %s", err)
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
					f.logger.Debugf("Already tailing file %s, not creating a new tail", event.Name)
					break
				}
				//Slightly different parameters for Location, as we want to read the first lines of the newly created file
				tail, err := tail.TailFile(event.Name, tail.Config{ReOpen: true, Follow: true, Poll: true, Location: &tail.SeekInfo{Offset: 0, Whence: io.SeekStart}})
				if err != nil {
					f.logger.Errorf("Could not start tailing file %s : %s", event.Name, err)
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
			f.logger.Errorf("Error while monitoring folder: %s", err)
		}
	}
}

func (f *FileSource) tailFile(out chan types.Event, t *tomb.Tomb, tail *tail.Tail) error {
	//lint:ignore SA1015 as it is an infinite loop
	timeout := time.Tick(1 * time.Second)
	f.logger.Debugf("-> Starting tail of %s", tail.Filename)
	for {
		l := types.Line{}
		select {
		case <-t.Dying():
			f.logger.Infof("File datasource %s stopping", tail.Filename)
			if err := tail.Stop(); err != nil {
				f.logger.Errorf("error in stop : %s", err)
			}
		case <-tail.Tomb.Dying(): //our tailer is dying
			f.logger.Warningf("File reader of %s died", tail.Filename)
			t.Kill(fmt.Errorf("dead reader for %s", tail.Filename))
			return fmt.Errorf("reader for %s is dead", tail.Filename)
		case line := <-tail.Lines:
			if line == nil {
				f.logger.Debugf("Nil line")
				return fmt.Errorf("tail for %s is empty", tail.Filename)
			}
			if line.Err != nil {
				log.Warningf("fetch error : %v", line.Err)
				return line.Err
			}
			if line.Text == "" { //skip empty lines
				continue
			}
			//FIXME: prometheus metrics
			//ReaderHits.With(prometheus.Labels{"source": tail.Filename}).Inc()

			l.Raw = line.Text
			l.Labels = f.config.Labels
			l.Time = line.Time
			l.Src = tail.Filename
			l.Process = true
			//we're tailing, it must be real time logs
			f.logger.Debugf("pushing %+v", l)
			out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
		case <-timeout:
			//time out, shall we do stuff ?
			f.logger.Trace("timeout")
		}
	}
}

func (f *FileSource) readFile(filename string, out chan types.Event, t *tomb.Tomb) error {
	var scanner *bufio.Scanner

	fd, err := os.Open(filename)

	if err != nil {
		return errors.Wrapf(err, "failed opening %s", filename)
	}
	defer fd.Close()

	if strings.HasSuffix(filename, ".gz") {
		gz, err := gzip.NewReader(fd)
		if err != nil {
			f.logger.Errorf("Failed to read gz file: %s", err)
			return errors.Wrapf(err, "failed to read gz %s", filename)
		}
		defer gz.Close()
		scanner = bufio.NewScanner(gz)

	} else {
		scanner = bufio.NewScanner(fd)
	}
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		f.logger.Debugf("line %s", scanner.Text())
		l := types.Line{}
		l.Raw = scanner.Text()
		l.Time = time.Now()
		l.Src = filename
		l.Labels = f.config.Labels
		l.Process = true

		//we're reading logs at once, it must be time-machine buckets
		out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.TIMEMACHINE}
	}
	t.Kill(nil)
	return nil
}
