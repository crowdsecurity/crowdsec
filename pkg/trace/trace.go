package trace

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/version"
)

// traceDir is where stack traces are dumped. It can be changed to a data directory
// by calling Init() after reading the configuration (i.e. config_paths.data_dir should be
// persistent even within containers)
var traceDir = os.TempDir()

var mutex = &sync.Mutex{}

const (
	// crashFileGlob is the glob pattern to match crash files
	crashFileGlob = "crowdsec-crash.*.txt"
	// keep stack traces for 30 days
	shelfLife = 30 * 24 * time.Hour
	// keep at most 100 stack traces
	maxTraces = 100
)

// Init sets the location of the trace files, to avoid passing them each time to CatchPanic()
func Init(dir string) {
	traceDir = dir
}

// List returns a list of all crash files in the trace directory
func List() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(traceDir, crashFileGlob))
	if err != nil {
		return nil, err
	}
	return files, nil
}

func Purge() {
	// Run in a mutex in case of concurrent, recoverable panics from apiserver
	mutex.Lock()
	defer mutex.Unlock()

	files, err := List()
	if err != nil {
		log.Errorf("error listing crash files for cleanup: %s", err)
		return
	}

	// Sort files by modification time, newest first
	sort.Slice(files, func(i, j int) bool {
		fi, err := os.Stat(files[i])
		if err != nil {
			return true
		}
		fj, err := os.Stat(files[j])
		if err != nil {
			return false
		}
		return fi.ModTime().After(fj.ModTime())
	})

	now := time.Now()
	kept := 0

	for _, file := range files {
		// keep at most maxTraces files
		if kept >= maxTraces {
			log.Infof("Removing excess trace file: %s", file)
			if err := os.Remove(file); err != nil {
				log.Errorf("error removing old crash file %s: %s", file, err)
			}
			continue
		}

		fi, err := os.Stat(file)
		if err != nil {
			log.Errorf("error stating file %s: %s", file, err)
			continue
		}

		// keep files younger than shelfLife
		if now.Sub(fi.ModTime()) > shelfLife {
			log.Infof("Removing excess trace file: %s", file)
			if err := os.Remove(file); err != nil {
				log.Errorf("error removing old crash file %s: %s", file, err)
			}
			continue
		}

		kept++
	}
}

// WriteStackTrace writes a stack trace to a file in the trace directory and returns the file name
func WriteStackTrace(iErr any) (string, error) {
	Purge()

	tmpfile, err := os.CreateTemp(traceDir, crashFileGlob)
	if err != nil {
		return "", err
	}
	defer tmpfile.Close()

	if _, err := fmt.Fprintf(tmpfile, "error: %+v\n", iErr); err != nil {
		return "", err
	}

	if _, err := tmpfile.WriteString(version.FullString()); err != nil {
		return "", err
	}

	if _, err := tmpfile.Write(debug.Stack()); err != nil {
		return "", err
	}

	return tmpfile.Name(), nil
}

// CatchPanic is a util func that we should call from all go-routines to ensure proper stacktrace handling
func CatchPanic(component string) {
	r := recover()
	if r == nil {
		return
	}

	log.Errorf("crowdsec - goroutine %s crashed: %s", component, r)
	log.Error("please report this error to https://github.com/crowdsecurity/crowdsec/issues")

	filename, err := WriteStackTrace(r)
	if err != nil {
		log.Errorf("unable to write stacktrace: %s", err)
	}

	log.Errorf("stacktrace/report is written to %s: please join it to your issue", filename)
	log.Fatal("crowdsec stopped")
}
