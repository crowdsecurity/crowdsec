package file_acquisition

import (
	"bufio"
	"compress/gzip"
	"fmt"
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
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

type FileConfiguration struct {
	Filenames []string
	Filename  string
	configuration.DataSourceCommonCfg
}

type FileSource struct {
	config  FileConfiguration
	watcher *fsnotify.Watcher
	logger  *log.Entry
	files   []string
}

func (f *FileSource) Configure(Config []byte, logger *log.Entry) error {
	fileConfig := FileConfiguration{}
	f.logger = logger
	err := yaml.Unmarshal(Config, &fileConfig)
	f.logger.Infof("%+v", fileConfig)
	if err != nil {
		f.logger.Errorf("Could not parse configuration for File datasource : %s", err)
		return err
	}
	if len(fileConfig.Filename) != 0 {
		fileConfig.Filenames = append(fileConfig.Filenames, fileConfig.Filename)
	}
	if len(fileConfig.Filenames) == 0 {
		f.logger.Errorf("No filename or filenames configuration provided")
		return errors.New("No filename or filenames configuration provided")
	}
	f.config = fileConfig
	f.config.Mode = configuration.TAIL_MODE
	f.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		f.logger.Errorf("Could not create fsnotify watcher : %s", err)
		return err
	}
	f.logger.Infof("%+v", f.config)
	for _, pattern := range f.config.Filenames {
		files, err := filepath.Glob(pattern)
		if err != nil {
			f.logger.Errorf("Glob failure: %s", err)
			return err
		}
		if len(files) == 0 {
			f.logger.Infof("No matching files for pattern %s", pattern)
			continue
		}
		for _, file := range files {
			f.logger.Infof("In config for file %s", file)
			f.logger.Infof("Files: %+v", files)
			f.logger.Infof("Mode: %s", f.config.Mode)
			if files[0] != pattern && f.config.Mode == configuration.TAIL_MODE { //we have a glob pattern
				//TODO: add only one watch per directory
				f.logger.Infof("Adding watch on %s", path.Dir(file))
				err = f.watcher.Add(path.Dir(file))
				if err != nil {
					f.logger.Errorf("Could not create watch on directory %s : %s", path.Dir(file), err)
					return err
				}
				f.logger.Infof("Adding file %s", file)
			}
			f.files = append(f.files, file)
		}
	}
	return nil
}

func (f *FileSource) GetMode() string {
	return f.config.Mode
}

func (f *FileSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}

func (f *FileSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	log.Infof("Starting oneshot acquisition on %d files", len(f.files))
	for _, filename := range f.files {
		log.Infof("reading %s at once", filename)
		err := f.readFile(filename, out, t)
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *FileSource) GetMetrics() []interface{} {
	return nil
}

func (f *FileSource) CanRun() bool {
	return true
}

func (f *FileSource) LiveAcquisition(out chan types.Event, t *tomb.Tomb) error {
	f.logger.Infof("Starting live acquisition")
	for _, file := range f.files {
		tail, err := tail.TailFile(file, tail.Config{ReOpen: true, Follow: true, Poll: true, Location: &tail.SeekInfo{Offset: 0, Whence: 2}})
		if err != nil {
			f.logger.Errorf("Could not start tailing file %s : %s", file, err)
			continue
		}
		t.Go(func() error {
			return f.monitorNewFiles(out, t)
		})
		t.Go(func() error {
			defer types.CatchPanic("crowdsec/acquis/file/live/fsnotify")
			return f.tailFile(out, t, tail)
		})
	}
	return nil
}

func (f *FileSource) monitorNewFiles(out chan types.Event, t *tomb.Tomb) error {
	for {
		select {
		case event, ok := <-f.watcher.Events:
			if !ok {
				return nil
			}
			log.Println("event:", event)
			if event.Op&fsnotify.Create == fsnotify.Create {
				f.logger.Infof("Detected new file %s", event.Name)
				tail, err := tail.TailFile(event.Name, tail.Config{ReOpen: true, Follow: true, Poll: true, Location: &tail.SeekInfo{Offset: 0, Whence: 2}})
				if err != nil {
					f.logger.Errorf("Could not start tailing file %s : %s", event.Name, err)
					continue
				}
				t.Go(func() error {
					defer types.CatchPanic("crowdsec/acquis/tailfile")
					return f.tailFile(out, t, tail)
				})
			}
		case err, ok := <-f.watcher.Errors:
			if !ok {
				return nil
			}
			log.Println("error:", err)
		}
	}
}

func (f *FileSource) tailFile(out chan types.Event, t *tomb.Tomb, tail *tail.Tail) error {
	//lint:ignore SA1015 as it is an infinite loop
	timeout := time.Tick(1 * time.Second)
	f.logger.Infof("-> Starting tail of %s", tail.Filename)
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
			//ReaderHits.With(prometheus.Labels{"source": tail.Filename}).Inc()

			l.Raw = line.Text
			l.Labels = f.config.Labels
			l.Time = line.Time
			l.Src = tail.Filename
			l.Process = true
			//we're tailing, it must be real time logs
			f.logger.Infof("pushing %+v", l)
			out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
		case <-timeout:
			//time out, shall we do stuff ?
			f.logger.Debugf("timeout")
		}
	}
}

func (f *FileSource) readFile(filename string, out chan types.Event, t *tomb.Tomb) error {
	var scanner *bufio.Scanner

	clog := log.WithFields(log.Fields{
		"file": filename,
	})
	fd, err := os.Open(filename)
	if err != nil {
		clog.Errorf("Failed opening file: %s", err)
		return errors.Wrapf(err, "failed opening %s", filename)
	}
	defer fd.Close()

	if strings.HasSuffix(filename, ".gz") {
		gz, err := gzip.NewReader(fd)
		if err != nil {
			clog.Errorf("Failed to read gz file: %s", err)
			return errors.Wrapf(err, "failed to read gz %s", filename)
		}
		defer gz.Close()
		scanner = bufio.NewScanner(gz)

	} else {
		scanner = bufio.NewScanner(fd)
	}
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		log.Infof("line %s", scanner.Text())
		l := types.Line{}
		l.Raw = scanner.Text()
		l.Time = time.Now()
		l.Src = filename
		l.Labels = f.config.Labels
		l.Process = true
		// FIXME: How to interact with prom metrics ?
		//ReaderHits.With(prometheus.Labels{"source": filename}).Inc()
		//we're reading logs at once, it must be time-machine buckets
		out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.TIMEMACHINE}
	}
	t.Kill(nil)
	return nil
}
