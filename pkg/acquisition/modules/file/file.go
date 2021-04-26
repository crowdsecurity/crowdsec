package file_acquisition

import (
	"bufio"
	"compress/gzip"
	"os"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/nxadm/tail"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

type FileConfiguration struct {
	Filenames []string
	Filename  string
}

type FileSource struct {
	CommonConfig configuration.DataSourceCommonCfg
	FileConfig   FileConfiguration
	tails        []*tail.Tail
	Files        []string
}

func (f *FileSource) Configure(Config []byte) error {
	log.Warn("Configuring FileSource")
	return nil
}

func (f *FileSource) Mode() string {
	return f.CommonConfig.Mode
}

func (f *FileSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}

func (f *FileSource) OneShotAcquisition(out chan types.Event, t *tomb.Tomb) error {
	for _, filename := range f.FileConfig.Filenames {
		log.Infof("reading %s at once", filename)
		err := f.readFile(filename, out, t)
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *FileSource) LiveAcquisition(out chan types.Event, t *tomb.Tomb) error {
	return nil
}

func (f *FileSource) New() *FileSource {
	log.Warn("Creating new FileSource")
	return &FileSource{}
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
		log.Tracef("line %s", scanner.Text())
		l := types.Line{}
		l.Raw = scanner.Text()
		l.Time = time.Now()
		l.Src = filename
		l.Labels = f.CommonConfig.Labels
		l.Process = true
		// FIXME: How to interact with prom metrics ?
		//ReaderHits.With(prometheus.Labels{"source": filename}).Inc()
		//we're reading logs at once, it must be time-machine buckets
		out <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.TIMEMACHINE}
	}
	t.Kill(nil)
	return nil
}
