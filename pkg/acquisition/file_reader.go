package acquisition

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/nxadm/tail"
	log "github.com/sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus"
	tomb "gopkg.in/tomb.v2"
)

type FileSource struct {
	Config DataSourceCfg
	tails  []*tail.Tail
	Files  []string
}

func (f *FileSource) Configure(Config DataSourceCfg) error {
	f.Config = Config
	if len(Config.Filename) == 0 && len(Config.Filenames) == 0 {
		return fmt.Errorf("no filename or filenames")
	}

	//let's deal with the array no matter what
	if len(Config.Filename) != 0 {
		Config.Filenames = append(Config.Filenames, Config.Filename)
	}

	for _, fexpr := range Config.Filenames {
		files, err := filepath.Glob(fexpr)
		if err != nil {
			return errors.Wrapf(err, "while globbing %s", fexpr)
		}
		if len(files) == 0 {
			log.Warningf("no results for %s", fexpr)
			continue
		}

		for _, file := range files {
			/*check that we can read said file*/
			if err := unix.Access(file, unix.R_OK); err != nil {
				log.Errorf("unable to open %s : %v", file, err)
				continue
			}
			log.Infof("Opening file '%s' (pattern:%s)", file, Config.Filename)

			tail, err := tail.TailFile(file, tail.Config{ReOpen: true, Follow: true, Poll: true, Location: &tail.SeekInfo{Offset: 0, Whence: 2}})
			if err != nil {
				log.Errorf("skipping %s : %v", file, err)
				continue
			}
			f.Files = append(f.Files, file)
			f.tails = append(f.tails, tail)
		}
	}

	log.Infof("appended : %d", len(f.Files))
	return nil
}

/*A tail-mode file reader (tail) */
func (f *FileSource) StartTail(output chan types.Event, AcquisTomb *tomb.Tomb) error {
	/*tbd instead use the tomb to lance subroutines*/
	log.Infof("starting file tail with %d items", len(f.tails))
	for i := 0; i < len(f.tails); i++ {
		idx := i
		log.Infof("starting %d", idx)
		AcquisTomb.Go(func() error {
			defer types.CatchPanic("crowdsec/acquis/file")
			return f.TailOneFile(output, AcquisTomb, idx)
		})
	}
	return nil
}

/*A one shot file reader (cat) */
func (f *FileSource) StartCat(output chan types.Event, AcquisTomb *tomb.Tomb) error {

	return nil
}

/*A tail-mode file reader (tail) */
func (f *FileSource) TailOneFile(output chan types.Event, AcquisTomb *tomb.Tomb, idx int) error {

	log.Infof("index = %d", idx)
	file := f.Files[idx]
	tail := f.tails[idx]

	clog := log.WithFields(log.Fields{
		"acquisition file": f.Files[idx],
	})
	clog.Debugf("starting")

	timeout := time.Tick(1 * time.Second)

	for {
		l := types.Line{}
		select {
		case <-AcquisTomb.Dying(): //we are being killed by main
			clog.Infof("Killing acquistion routine")
			if err := tail.Stop(); err != nil {
				clog.Errorf("error in stop : %s", err)
			}
			return nil
		case <-tail.Tomb.Dying(): //our tailer is dying
			clog.Warningf("Reader is dying/dead")
			return fmt.Errorf("reader for %s is dead", file)
		case line := <-tail.Lines:
			if line == nil {
				clog.Debugf("Nil line")
				return fmt.Errorf("tail for %s is empty", file)
			}
			if line.Err != nil {
				log.Warningf("fetch error : %v", line.Err)
				return line.Err
			}
			if line.Text == "" { //skip empty lines
				continue
			}
			ReaderHits.With(prometheus.Labels{"source": file}).Inc()

			l.Raw = line.Text
			l.Labels = f.Config.Labels
			l.Time = line.Time
			l.Src = file
			l.Process = true
			//we're tailing, it must be real time logs
			log.Infof("pushing %+v", l)
			output <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
		case <-timeout:
			//time out, shall we do stuff ?
			clog.Debugf("timeout")
		}
	}
	return nil
}

/*A one shot file reader (cat) */
func (f *FileSource) CatOneFile(output chan types.Event, AcquisTomb *tomb.Tomb, idx int) error {
	var scanner *bufio.Scanner

	log.Infof("reading %s at once", f.Files[idx])
	file := f.Files[idx]

	clog := log.WithFields(log.Fields{
		"file": file,
	})
	fd, err := os.Open(file)
	defer fd.Close()
	if err != nil {
		clog.Errorf("Failed opening file: %s", err)
		return errors.Wrapf(err, "failed opening %s", f.Files[idx])
	}

	if strings.HasSuffix(file, ".gz") {
		gz, err := gzip.NewReader(fd)
		if err != nil {
			clog.Errorf("Failed to read gz file: %s", err)
			return errors.Wrapf(err, "failed to read gz %s", f.Files[idx])
		}
		defer gz.Close()
		scanner = bufio.NewScanner(gz)

	} else {
		scanner = bufio.NewScanner(fd)
	}
	scanner.Split(bufio.ScanLines)
	count := 0
	for scanner.Scan() {
		log.Tracef("line %s", scanner.Text())
		count++
		l := types.Line{}
		l.Raw = scanner.Text()
		l.Time = time.Now()
		l.Src = file
		l.Labels = f.Config.Labels
		l.Process = true
		//we're reading logs at once, it must be time-machine buckets
		output <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.TIMEMACHINE}
	}
	clog.Warningf("read %d lines", count)
	AcquisTomb.Kill(nil)
	return nil
}
