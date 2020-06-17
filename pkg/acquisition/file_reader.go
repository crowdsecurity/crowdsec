package acquisition

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

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
		Name: "cs_reader_hits",
		Help: "How many lines where read.",
	},
	[]string{"source"},
)

func LoadAcquisitionConfig(cConfig *csconfig.CrowdSec) (*FileAcquisCtx, error) {
	var acquisitionCTX *FileAcquisCtx
	var err error
	/*Init the acqusition : from cli or from acquis.yaml file*/
	if cConfig.SingleFile != "" {
		var input FileCtx
		input.Filename = cConfig.SingleFile
		input.Mode = CATMODE
		input.Labels = make(map[string]string)
		input.Labels["type"] = cConfig.SingleFileLabel
		acquisitionCTX, err = InitReaderFromFileCtx([]FileCtx{input})
	} else { /* Init file reader if we tail */
		acquisitionCTX, err = InitReader(cConfig.AcquisitionFile)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to start file acquisition, bailout %v", err)
	}
	if acquisitionCTX == nil {
		return nil, fmt.Errorf("no inputs to process")
	}
	if cConfig.Profiling {
		acquisitionCTX.Profiling = true
	}

	return acquisitionCTX, nil
}

func InitReader(cfg string) (*FileAcquisCtx, error) {
	var files []FileCtx

	yamlFile, err := os.Open(cfg)
	if err != nil {
		log.Errorf("Can't access acquisition configuration file with '%v'.", err)
		return nil, err
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
			log.Fatalf("Error decoding acquisition configuration file with '%s': %v", cfg, err)
			break
		}
		files = append(files, t)
	}
	return InitReaderFromFileCtx(files)
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
			log.Infof("No filename or filenames, skipping empty item %+v", t)
			continue
		}
		if len(t.Labels) == 0 {
			log.Infof("Acquisition has no tags, skipping empty item %+v", t)
			continue
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
				log.Errorf("error while globing '%s' : %v", fglob, err)
				return nil, err
			}

			for _, file := range files {
				/*check that we can read said file*/
				if err := unix.Access(file, unix.R_OK); err != nil {
					log.Errorf("Unable to open file [%s] : %v", file, err)
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
							log.Errorf("skipping '%s' : %v", file, err)
							continue
						}
					}
				case BINTYPE:

				default:
					log.Fatalf("unexpected type %s for %+v", t.Type, t.Filenames)
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
func AcquisStartReading(ctx *FileAcquisCtx, output chan types.Event, AcquisTomb *tomb.Tomb) {

	if len(ctx.Files) == 0 {
		log.Errorf("No files to read")
	}
	/* start one go routine reading for each file, and pushing to chan output */
	for idx, fctx := range ctx.Files {
		log.Printf("starting reader file %d/%d : %s", idx, len(ctx.Files), fctx.Filename)
		if ctx.Profiling {
			fctx.Profiling = true
		}
		fctx := fctx
		switch fctx.Mode {
		case TAILMODE:
			AcquisTomb.Go(func() error {
				return AcquisReadOneFile(fctx, output, AcquisTomb)
			})
		case CATMODE:
			AcquisTomb.Go(func() error {
				return ReadAtOnce(fctx, output, AcquisTomb)
			})
		default:
			log.Fatalf("unknown read mode %s for %+v", fctx.Mode, fctx.Filenames)
		}
	}
	log.Printf("Started %d routines for polling/read", len(ctx.Files))
}

/*A tail-mode file reader (tail) */
func AcquisReadOneFile(ctx FileCtx, output chan types.Event, AcquisTomb *tomb.Tomb) error {
	clog := log.WithFields(log.Fields{
		"acquisition file": ctx.Filename,
	})

	if ctx.Type != FILETYPE {
		log.Errorf("Can't tail %s type for %+v", ctx.Type, ctx.Filenames)
		return fmt.Errorf("can't tail %s type for %+v", ctx.Type, ctx.Filenames)
	}
	log.Infof("Starting tail of %s", ctx.Filename)
	timeout := time.Tick(20 * time.Second)
LOOP:
	for {
		l := types.Line{}
		select {
		case <-AcquisTomb.Dying(): //we are being killed by main
			clog.Infof("Killing acquistion routine")
			if err := ctx.tail.Stop(); err != nil {
				clog.Warningf("error in stop : %s", err)
			}
			break LOOP
		case <-ctx.tail.Tomb.Dying(): //our tailer is dying
			clog.Warningf("Reader is dying/dead")
			return errors.New("reader is dead")
		case line := <-ctx.tail.Lines:
			if line == nil {
				clog.Debugf("Nil line")
				return errors.New("Tail is empty")
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
func ReadAtOnce(ctx FileCtx, output chan types.Event, AcquisTomb *tomb.Tomb) error {
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
		return err
	}

	if ctx.Type == FILETYPE {
		if strings.HasSuffix(file, ".gz") {
			gz, err := gzip.NewReader(fd)
			if err != nil {
				clog.Errorf("Failed to read gz file: %s", err)
				return err
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
