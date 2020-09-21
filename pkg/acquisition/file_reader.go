package acquisition

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"

	tomb "gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"

	//"log"
	"path/filepath"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/nxadm/tail"
)

type Acquisition interface {
	Init(map[string]interface{}) (interface{}, error)
	ReadOne(interface{}) (string, error)
}

type FileCtx struct {
	Type      string   `yaml:"type,omitempty"` //file|bin|...
	Mode      string   `yaml:"mode,omitempty"` //tail|cat|...
	Filename  string   `yaml:"filename,omitempty"`
	Filenames []string `yaml:"filenames,omitempty"`
	tail      *tail.Tail

	Labels    map[string]string `yaml:"labels,omitempty"`
	Profiling bool              `yaml:"profiling,omitempty"`
}

type FileAcquisCtx struct {
	Files     []FileCtx
	Profiling bool
}

const (
	TAILMODE = "tail"
	CATMODE  = "cat"
)

const (
	FILETYPE = "file"
	BINTYPE  = "bin"
)

var ReaderHits = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_reader_hits_total",
		Help: "Total lines where read.",
	},
	[]string{"source"},
)

/*LoadAcquisCtxSingleFile Loading a single file path/type for acquisition*/
func LoadAcquisCtxSingleFile(path string, filetype string) ([]FileCtx, error) {
	var input FileCtx
	input.Filename = path
	input.Mode = CATMODE
	input.Labels = make(map[string]string)
	input.Labels["type"] = filetype
	return []FileCtx{input}, nil
}

/*LoadAcquisCtxConfigFile Loading a acquis.yaml file for acquisition*/
func LoadAcquisCtxConfigFile(config *csconfig.CrowdsecServiceCfg) ([]FileCtx, error) {
	var files []FileCtx

	if config == nil || config.AcquisitionFilePath == "" {
		return nil, fmt.Errorf("missing config or acquisition file path")
	}
	yamlFile, err := os.Open(config.AcquisitionFilePath)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("can't open %s", config.AcquisitionFilePath))
	}
	//process the yaml
	dec := yaml.NewDecoder(yamlFile)
	dec.SetStrict(true)
	for {
		t := FileCtx{}
		err = dec.Decode(&t)
		if err != nil {
			if err == io.EOF {
				log.Tracef("End of yaml file")
				break
			}
			return nil, errors.Wrap(err, fmt.Sprintf("failed to yaml decode %s", config.AcquisitionFilePath))
		}
		files = append(files, t)
	}
	return files, nil
}

//InitReader iterates over the FileCtx objects of cfg and resolves globbing to open files
func InitReaderFromFileCtx(files []FileCtx) (*FileAcquisCtx, error) {

	var ctx *FileAcquisCtx = &FileAcquisCtx{}

	for _, t := range files {
		//defaults to file type in tail mode.
		if t.Type == "" {
			t.Type = FILETYPE
		}
		if t.Mode == "" {
			t.Mode = TAILMODE
		}
		//minimalist sanity check
		if t.Filename == "" && len(t.Filenames) == 0 {
			return nil, fmt.Errorf("no filename in %+v", t)
		}
		if len(t.Labels) == 0 {
			return nil, fmt.Errorf("no tags in %+v", t)
		}

		if len(t.Filename) > 0 {
			t.Filenames = append(t.Filenames, t.Filename)
		}
		var opcpt int
		//open the files indicated by `filename` and `filesnames`
		for _, fglob := range t.Filenames {
			opcpt = 0
			files, err := filepath.Glob(fglob)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("while globbing %s", fglob))
			}
			if len(files) == 0 {
				log.Warningf("no results for %s", fglob)
				continue
			}
			for _, file := range files {
				/*check that we can read said file*/
				if err := unix.Access(file, unix.R_OK); err != nil {
					log.Errorf("unable to open %s : %v", file, err)
					continue
				}
				log.Infof("Opening file '%s' (pattern:%s)", file, fglob)
				fdesc := t
				fdesc.Filename = file
				fdesc.Filenames = []string{}

				switch t.Type {
				case FILETYPE:
					if t.Mode == TAILMODE {
						fdesc.tail, err = tail.TailFile(file, tail.Config{ReOpen: true, Follow: true, Poll: true, Location: &tail.SeekInfo{Offset: 0, Whence: 2}})
						if err != nil {
							log.Errorf("skipping %s : %v", file, err)
							continue
						}
					}
				case BINTYPE:

				default:
					return nil, fmt.Errorf("%s is of unknown type %s", file, t.Type)
				}
				opcpt++
				ctx.Files = append(ctx.Files, fdesc)
			}
		}
		log.Debugf("'%v' opened %d files", t.Filenames, opcpt)
	}
	return ctx, nil
}

//let's return an array of chans for signaling for now
func AcquisStartReading(ctx *FileAcquisCtx, output chan types.Event, AcquisTomb *tomb.Tomb) error {

	if len(ctx.Files) == 0 {
		return fmt.Errorf("no files to read")
	}
	/* start one go routine reading for each file, and pushing to chan output */
	for idx, fctx := range ctx.Files {
		if ctx.Profiling {
			fctx.Profiling = true
		}
		fctx := fctx
		mode := "?"
		switch fctx.Mode {
		case TAILMODE:
			mode = "tail"
			AcquisTomb.Go(func() error {
				return TailFile(fctx, output, AcquisTomb)
			})
		case CATMODE:
			mode = "cat"
			AcquisTomb.Go(func() error {
				return CatFile(fctx, output, AcquisTomb)
			})
		default:
			return fmt.Errorf("unknown read mode %s for %+v", fctx.Mode, fctx.Filenames)
		}
		log.Printf("starting (%s) reader file %d/%d : %s", mode, idx, len(ctx.Files), fctx.Filename)
	}
	log.Printf("Started %d routines for polling/read", len(ctx.Files))
	return nil
}

/*A tail-mode file reader (tail) */
func TailFile(ctx FileCtx, output chan types.Event, AcquisTomb *tomb.Tomb) error {
	clog := log.WithFields(log.Fields{
		"acquisition file": ctx.Filename,
	})
	if ctx.Type != FILETYPE {
		return fmt.Errorf("can't tail %s type for %s", ctx.Type, ctx.Filename)
	}
	clog.Infof("Starting tail")
	timeout := time.Tick(20 * time.Second)
LOOP:
	for {
		l := types.Line{}
		select {
		case <-AcquisTomb.Dying(): //we are being killed by main
			clog.Infof("Killing acquistion routine")
			if err := ctx.tail.Stop(); err != nil {
				clog.Errorf("error in stop : %s", err)
			}
			break LOOP
		case <-ctx.tail.Tomb.Dying(): //our tailer is dying
			clog.Warningf("Reader is dying/dead")
			return fmt.Errorf("reader for %s is dead", ctx.Filename)
		case line := <-ctx.tail.Lines:
			if line == nil {
				clog.Debugf("Nil line")
				return fmt.Errorf("tail for %s is empty", ctx.Filename)
			}
			if line.Err != nil {
				log.Warningf("fetch error : %v", line.Err)
				return line.Err
			}
			if line.Text == "" { //skip empty lines
				continue
			}
			ReaderHits.With(prometheus.Labels{"source": ctx.Filename}).Inc()

			l.Raw = line.Text
			l.Labels = ctx.Labels
			l.Time = line.Time
			l.Src = ctx.Filename
			l.Process = true
			//we're tailing, it must be real time logs
			output <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.LIVE}
		case <-timeout:
			//time out, shall we do stuff ?
			clog.Tracef("timeout")
		}
	}
	return nil
}

/*A one shot file reader (cat) */
func CatFile(ctx FileCtx, output chan types.Event, AcquisTomb *tomb.Tomb) error {
	var scanner *bufio.Scanner

	if len(ctx.Filenames) > 0 {
		log.Errorf("no multi-file support for this mode.")
		return fmt.Errorf("no multi-file support for this mode")
	}
	log.Infof("reading %s at once", ctx.Filename)
	file := ctx.Filename

	clog := log.WithFields(log.Fields{
		"file": file,
	})
	fd, err := os.Open(file)
	defer fd.Close()
	if err != nil {
		clog.Errorf("Failed opening file: %s", err)
		return errors.Wrap(err, fmt.Sprintf("failed opening %s", ctx.Filename))
	}

	if ctx.Type == FILETYPE {
		if strings.HasSuffix(file, ".gz") {
			gz, err := gzip.NewReader(fd)
			if err != nil {
				clog.Errorf("Failed to read gz file: %s", err)
				return errors.Wrap(err, fmt.Sprintf("failed to read gz %s", ctx.Filename))
			}
			defer gz.Close()
			scanner = bufio.NewScanner(gz)

		} else {
			scanner = bufio.NewScanner(fd)
		}
		scanner.Split(bufio.ScanLines)
		count := 0
		for scanner.Scan() {
			count++
			l := types.Line{}
			l.Raw = scanner.Text()
			l.Time = time.Now()
			l.Src = file
			l.Labels = ctx.Labels
			l.Process = true
			//we're reading logs at once, it must be time-machine buckets
			output <- types.Event{Line: l, Process: true, Type: types.LOG, ExpectMode: leaky.TIMEMACHINE}
		}
		clog.Warningf("read %d lines", count)
	} else if ctx.Type == BINTYPE {
		/*BINTYPE is only overflows for now*/
		dec := json.NewDecoder(fd)
		count := 0
		for {
			var p types.Event
			if err := dec.Decode(&p); err == io.EOF {
				break
			} else if err != nil {
				log.Warningf("While reading %s : %s", fd.Name(), err)
				continue
			}
			count++
			p.Type = types.OVFLW
			p.Process = true
			//we're reading logs at once, it must be time-machine buckets
			p.ExpectMode = leaky.TIMEMACHINE
			output <- p
		}
		clog.Warningf("unmarshaled %d events", count)

	}
	clog.Infof("force commit")
	return nil
}
